using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class MftCollector : ICollector
{
    public string Name => "MFT";
    public string Description => "Raw $MFT (Master File Table)";

    #region P/Invoke

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(
        out IntPtr FileHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        out IO_STATUS_BLOCK IoStatusBlock,
        IntPtr AllocationSize,
        uint FileAttributes,
        uint ShareAccess,
        uint CreateDisposition,
        uint CreateOptions,
        IntPtr EaBuffer,
        uint EaLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(
        IntPtr hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr prev, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    private struct DataRun
    {
        public long StartCluster;
        public long LengthInClusters;
    }

    private const uint FILE_READ_DATA = 0x0001;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint FILE_OPEN = 0x01;
    private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
    private const uint FILE_NON_DIRECTORY_FILE = 0x40;
    private const uint FILE_OPEN_FOR_BACKUP_INTENT = 0x4000;
    private const uint OBJ_CASE_INSENSITIVE = 0x40;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x02;
    private const uint GENERIC_READ = 0x80000000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_BEGIN = 0;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    #endregion

    private readonly List<string> _errors = new();

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "mft");
        Directory.CreateDirectory(destDir);
        var dest = Path.Combine(destDir, "$MFT");

        EnablePrivilege("SeBackupPrivilege");
        EnablePrivilege("SeManageVolumePrivilege");

        // Strategy 0: Raw volume read (reads MFT at disk offset, bypasses NTFS metafile restrictions)
        if (TryRawVolumeRead(dest))
            return MakeResult(sw, dest, context, "raw volume");

        // Strategy 1: NtCreateFile (native NT API)
        if (TryNtCreateFileCopy(dest))
            return MakeResult(sw, dest, context, "NtCreateFile");

        // Strategy 2: Direct FileStream read
        if (TryDirectRead(dest))
            return MakeResult(sw, dest, context, "direct read");

        var allErrors = string.Join("; ", _errors);
        ConsoleOutput.Error($"  MFT: all methods failed -- {allErrors}");

        return new CollectorResult
        {
            CollectorName = Name,
            Error = $"All $MFT extraction methods failed: {allErrors}",
            Elapsed = sw.Elapsed
        };
    }

    /// <summary>
    /// TSK-inspired raw volume strategy: opens \\.\C: as a device, reads the NTFS boot sector
    /// to locate the MFT on disk, parses MFT entry 0's $DATA attribute data runs, then
    /// streams the entire MFT from raw disk sectors to the output file.
    /// </summary>
    private bool TryRawVolumeRead(string dest)
    {
        IntPtr hVol = INVALID_HANDLE_VALUE;
        try
        {
            hVol = CreateFile(@"\\.\C:", GENERIC_READ, 0x01 | 0x02,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

            if (hVol == IntPtr.Zero || hVol == INVALID_HANDLE_VALUE)
            {
                int err = Marshal.GetLastWin32Error();
                _errors.Add($"RawVolume: CreateFile on \\\\.\\C: failed (Win32={err})");
                ConsoleOutput.Warning($"  MFT RawVolume: CreateFile failed (Win32 err={err})");
                return false;
            }

            byte[] bootSector = new byte[512];
            if (!ReadFile(hVol, bootSector, 512, out uint bootRead, IntPtr.Zero) || bootRead < 512)
            {
                _errors.Add("RawVolume: Failed to read boot sector");
                return false;
            }

            string magic = Encoding.ASCII.GetString(bootSector, 3, 4);
            if (magic != "NTFS")
            {
                _errors.Add($"RawVolume: Not NTFS (magic='{magic}')");
                return false;
            }

            ushort sectorSize = BitConverter.ToUInt16(bootSector, 11);
            byte sectorsPerCluster = bootSector[13];
            long mftCluster = BitConverter.ToInt64(bootSector, 48);
            sbyte mftRecSizeInd = (sbyte)bootSector[64];

            int bytesPerCluster = sectorSize * sectorsPerCluster;
            long mftOffset = mftCluster * bytesPerCluster;

            int mftRecordSize = mftRecSizeInd > 0
                ? mftRecSizeInd * bytesPerCluster
                : 1 << (-mftRecSizeInd);

            ConsoleOutput.Status($"  MFT RawVolume: NTFS sector={sectorSize} cluster={bytesPerCluster} " +
                                 $"MFT@cluster {mftCluster} (offset 0x{mftOffset:X}) record={mftRecordSize}B");

            if (!SetFilePointerEx(hVol, mftOffset, out _, FILE_BEGIN))
            {
                int err = Marshal.GetLastWin32Error();
                _errors.Add($"RawVolume: Seek to MFT failed (Win32={err})");
                return false;
            }

            byte[] mftEntry0 = new byte[mftRecordSize];
            if (!ReadFile(hVol, mftEntry0, (uint)mftRecordSize, out uint entryRead, IntPtr.Zero)
                || entryRead < mftRecordSize)
            {
                _errors.Add("RawVolume: Failed to read MFT entry 0");
                return false;
            }

            string fileMagic = Encoding.ASCII.GetString(mftEntry0, 0, 4);
            if (fileMagic != "FILE")
            {
                _errors.Add($"RawVolume: MFT entry 0 bad magic ('{fileMagic}')");
                return false;
            }

            ApplyFixups(mftEntry0, mftRecordSize, sectorSize);

            var dataRuns = ParseMftDataRuns(mftEntry0, mftRecordSize);
            if (dataRuns == null || dataRuns.Count == 0)
            {
                _errors.Add("RawVolume: Could not parse $DATA runs from MFT entry 0");
                return false;
            }

            long totalMftSize = 0;
            foreach (var run in dataRuns)
                totalMftSize += run.LengthInClusters * bytesPerCluster;

            ConsoleOutput.Status($"  MFT RawVolume: {dataRuns.Count} data run(s), " +
                                 $"total {FileHelper.FormatSize(totalMftSize)}");

            byte[] buffer = new byte[1024 * 1024];
            long totalWritten = 0;

            using var outStream = new FileStream(dest, FileMode.Create, FileAccess.Write,
                FileShare.None, 1024 * 1024);

            foreach (var run in dataRuns)
            {
                long runOffset = run.StartCluster * bytesPerCluster;
                long runLength = run.LengthInClusters * bytesPerCluster;

                if (!SetFilePointerEx(hVol, runOffset, out _, FILE_BEGIN))
                {
                    _errors.Add($"RawVolume: Seek failed to offset 0x{runOffset:X}");
                    return false;
                }

                long remaining = runLength;
                while (remaining > 0)
                {
                    uint toRead = (uint)Math.Min(remaining, buffer.Length);
                    if (!ReadFile(hVol, buffer, toRead, out uint bytesRead, IntPtr.Zero) || bytesRead == 0)
                    {
                        int err = Marshal.GetLastWin32Error();
                        _errors.Add($"RawVolume: ReadFile failed (Win32={err}, remaining={remaining})");
                        return false;
                    }

                    outStream.Write(buffer, 0, (int)bytesRead);
                    totalWritten += bytesRead;
                    remaining -= bytesRead;

                    if (totalWritten % (100 * 1024 * 1024) == 0)
                        ConsoleOutput.Status($"  MFT RawVolume: {FileHelper.FormatSize(totalWritten)} / " +
                                             $"{FileHelper.FormatSize(totalMftSize)}...");
                }
            }

            outStream.Flush();
            ConsoleOutput.Status($"  MFT RawVolume: {FileHelper.FormatSize(totalWritten)} total captured");
            return totalWritten > 0;
        }
        catch (Exception ex)
        {
            _errors.Add($"RawVolume: {ex.Message}");
            ConsoleOutput.Warning($"  MFT RawVolume exception: {ex.Message}");
            try { if (File.Exists(dest)) File.Delete(dest); } catch { }
            return false;
        }
        finally
        {
            if (hVol != IntPtr.Zero && hVol != INVALID_HANDLE_VALUE)
                CloseHandle(hVol);
        }
    }

    /// <summary>
    /// Applies NTFS fixup array: replaces the last 2 bytes of each sector
    /// with the stored fixup values (reverses the write-time fixup).
    /// </summary>
    private static void ApplyFixups(byte[] record, int recordSize, ushort sectorSize)
    {
        ushort fixupOffset = BitConverter.ToUInt16(record, 4);
        ushort fixupCount = BitConverter.ToUInt16(record, 6);

        if (fixupCount < 2 || fixupOffset + fixupCount * 2 > recordSize)
            return;

        for (int i = 1; i < fixupCount; i++)
        {
            int sectorEnd = i * sectorSize - 2;
            if (sectorEnd + 1 >= recordSize)
                break;

            ushort replacement = BitConverter.ToUInt16(record, fixupOffset + i * 2);
            record[sectorEnd] = (byte)(replacement & 0xFF);
            record[sectorEnd + 1] = (byte)(replacement >> 8);
        }
    }

    /// <summary>
    /// Walks the attributes of MFT entry 0 to find the non-resident $DATA attribute (type 0x80),
    /// then parses its data run list to get the on-disk extents of the entire MFT.
    /// </summary>
    private static List<DataRun>? ParseMftDataRuns(byte[] record, int recordSize)
    {
        ushort attrOffset = BitConverter.ToUInt16(record, 20);

        while (attrOffset + 16 <= recordSize)
        {
            uint attrType = BitConverter.ToUInt32(record, attrOffset);
            if (attrType == 0xFFFFFFFF)
                break;

            uint attrLength = BitConverter.ToUInt32(record, attrOffset + 4);
            if (attrLength == 0 || attrOffset + attrLength > recordSize)
                break;

            if (attrType == 0x80) // $DATA
            {
                byte nonResident = record[attrOffset + 8];
                if (nonResident == 0)
                    return null; // MFT $DATA should never be resident

                ushort dataRunOff = BitConverter.ToUInt16(record, attrOffset + 32);
                int runStart = attrOffset + dataRunOff;
                return ParseDataRuns(record, runStart, attrOffset + (int)attrLength);
            }

            attrOffset += (ushort)attrLength;
        }

        return null;
    }

    /// <summary>
    /// Parses NTFS data run list: each run is a header byte (low nibble = length-field bytes,
    /// high nibble = offset-field bytes), followed by the length (unsigned LE) and offset
    /// (signed LE, relative to previous run). Terminated by 0x00.
    /// </summary>
    private static List<DataRun> ParseDataRuns(byte[] data, int offset, int limit)
    {
        var runs = new List<DataRun>();
        long prevCluster = 0;

        while (offset < limit)
        {
            byte header = data[offset];
            if (header == 0x00)
                break;

            int lengthSize = header & 0x0F;
            int offsetSize = (header >> 4) & 0x0F;
            offset++;

            if (offset + lengthSize + offsetSize > limit)
                break;

            long length = 0;
            for (int i = 0; i < lengthSize; i++)
                length |= (long)data[offset + i] << (i * 8);
            offset += lengthSize;

            if (offsetSize == 0)
                continue; // sparse run

            long runOffset = 0;
            for (int i = 0; i < offsetSize; i++)
                runOffset |= (long)data[offset + i] << (i * 8);

            if ((data[offset + offsetSize - 1] & 0x80) != 0)
            {
                for (int i = offsetSize; i < 8; i++)
                    runOffset |= unchecked((long)0xFF) << (i * 8);
            }
            offset += offsetSize;

            long absCluster = prevCluster + runOffset;
            prevCluster = absCluster;

            runs.Add(new DataRun { StartCluster = absCluster, LengthInClusters = length });
        }

        return runs;
    }

    private bool TryNtCreateFileCopy(string dest)
    {
        var handles = new List<IntPtr>();
        try
        {
            string ntPath = @"\??\C:\$MFT";
            byte[] pathBytes = Encoding.Unicode.GetBytes(ntPath);

            IntPtr pPathBuf = Marshal.AllocHGlobal(pathBytes.Length + 2);
            handles.Add(pPathBuf);
            Marshal.Copy(pathBytes, 0, pPathBuf, pathBytes.Length);
            Marshal.WriteInt16(pPathBuf, pathBytes.Length, 0);

            int unicodeStringSize = IntPtr.Size == 8 ? 16 : 8;
            IntPtr pUnicodeString = Marshal.AllocHGlobal(unicodeStringSize);
            handles.Add(pUnicodeString);
            Marshal.WriteInt16(pUnicodeString, 0, (short)pathBytes.Length);
            Marshal.WriteInt16(pUnicodeString, 2, (short)(pathBytes.Length + 2));
            if (IntPtr.Size == 8)
                Marshal.WriteIntPtr(pUnicodeString, 8, pPathBuf);
            else
                Marshal.WriteIntPtr(pUnicodeString, 4, pPathBuf);

            int oaSize = IntPtr.Size == 8 ? 48 : 24;
            IntPtr pObjAttr = Marshal.AllocHGlobal(oaSize);
            handles.Add(pObjAttr);

            for (int i = 0; i < oaSize; i++)
                Marshal.WriteByte(pObjAttr, i, 0);

            if (IntPtr.Size == 8)
            {
                Marshal.WriteInt32(pObjAttr, 0, oaSize);
                Marshal.WriteIntPtr(pObjAttr, 8, IntPtr.Zero);
                Marshal.WriteIntPtr(pObjAttr, 16, pUnicodeString);
                Marshal.WriteInt32(pObjAttr, 24, (int)OBJ_CASE_INSENSITIVE);
                Marshal.WriteIntPtr(pObjAttr, 32, IntPtr.Zero);
                Marshal.WriteIntPtr(pObjAttr, 40, IntPtr.Zero);
            }
            else
            {
                Marshal.WriteInt32(pObjAttr, 0, oaSize);
                Marshal.WriteIntPtr(pObjAttr, 4, IntPtr.Zero);
                Marshal.WriteIntPtr(pObjAttr, 8, pUnicodeString);
                Marshal.WriteInt32(pObjAttr, 12, (int)OBJ_CASE_INSENSITIVE);
                Marshal.WriteIntPtr(pObjAttr, 16, IntPtr.Zero);
                Marshal.WriteIntPtr(pObjAttr, 20, IntPtr.Zero);
            }

            int status = NtCreateFile(
                out IntPtr fileHandle,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                pObjAttr,
                out _,
                IntPtr.Zero,
                0,
                0x01 | 0x02,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
                IntPtr.Zero,
                0);

            if (status != 0 || fileHandle == IntPtr.Zero || fileHandle == new IntPtr(-1))
            {
                string msg = $"NtCreateFile: NTSTATUS=0x{status:X8} (Win32 err={Marshal.GetLastWin32Error()})";
                _errors.Add(msg);
                ConsoleOutput.Warning($"  MFT {msg}");
                if (fileHandle != IntPtr.Zero && fileHandle != new IntPtr(-1))
                    CloseHandle(fileHandle);
                return false;
            }

            ConsoleOutput.Status("  MFT: NtCreateFile opened $MFT successfully, copying...");

            using var safeHandle = new SafeFileHandle(fileHandle, ownsHandle: true);
            using var src = new FileStream(safeHandle, FileAccess.Read, 1024 * 1024, false);
            using var dst = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024);

            var buffer = new byte[1024 * 1024];
            long totalWritten = 0;
            int read;

            while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
            {
                dst.Write(buffer, 0, read);
                totalWritten += read;

                if (totalWritten % (100 * 1024 * 1024) == 0)
                    ConsoleOutput.Status($"  MFT: {FileHelper.FormatSize(totalWritten)} read...");
            }

            dst.Flush();
            ConsoleOutput.Status($"  MFT: {FileHelper.FormatSize(totalWritten)} total");
            return totalWritten > 0;
        }
        catch (Exception ex)
        {
            _errors.Add($"NtCreateFile: {ex.Message}");
            ConsoleOutput.Warning($"  MFT NtCreateFile exception: {ex.Message}");
            try { if (File.Exists(dest)) File.Delete(dest); } catch { }
            return false;
        }
        finally
        {
            foreach (var h in handles)
                Marshal.FreeHGlobal(h);
        }
    }

    private bool TryDirectRead(string dest)
    {
        try
        {
            using var src = new FileStream(@"C:\$MFT", FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1024 * 1024);
            using var dst = new FileStream(dest, FileMode.Create, FileAccess.Write,
                FileShare.None, 1024 * 1024);
            src.CopyTo(dst, 1024 * 1024);
            return new FileInfo(dest).Length > 0;
        }
        catch (Exception ex)
        {
            _errors.Add($"DirectRead: {ex.Message}");
            ConsoleOutput.Warning($"  MFT direct read: {ex.Message}");
            try { if (File.Exists(dest)) File.Delete(dest); } catch { }
            return false;
        }
    }

    private static void EnablePrivilege(string privilegeName)
    {
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            {
                ConsoleOutput.Warning($"  MFT: OpenProcessToken failed for {privilegeName} (err={Marshal.GetLastWin32Error()})");
                return;
            }
            if (!LookupPrivilegeValue(null, privilegeName, out var luid))
            {
                ConsoleOutput.Warning($"  MFT: LookupPrivilegeValue failed for {privilegeName} (err={Marshal.GetLastWin32Error()})");
                CloseHandle(token);
                return;
            }

            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int adjustErr = Marshal.GetLastWin32Error();
            if (adjustErr != 0)
                ConsoleOutput.Warning($"  MFT: AdjustTokenPrivileges for {privilegeName} returned err={adjustErr}");
            CloseHandle(token);
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"  MFT: EnablePrivilege({privilegeName}) exception: {ex.Message}");
        }
    }

    private CollectorResult MakeResult(Stopwatch sw, string dest, CollectionContext context, string method)
    {
        var size = new FileInfo(dest).Length;
        ConsoleOutput.Status($"  $MFT captured via {method} ({FileHelper.FormatSize(size)})");
        context.CollectedFiles.Add(new CollectedFileEntry
        {
            OriginalPath = @"C:\$MFT",
            RelativePath = Path.GetRelativePath(context.OutputDir, dest),
            Category = "mft",
            Size = size
        });

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = 1,
            BytesCollected = size,
            Elapsed = sw.Elapsed
        };
    }
}
