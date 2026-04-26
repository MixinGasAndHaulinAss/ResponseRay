using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Reads the NTFS USN change journal ($UsnJrnl:$J) for every fixed NTFS volume and writes
/// the parsed records out as JSONL. We avoid copying the raw sparse stream because it can
/// be tens of GB; the parsed JSONL captures the same forensic content (file create/rename/delete
/// history) at a fraction of the size.
/// </summary>
public class UsnJournalCollector : ICollector
{
    public string Name => "UsnJournal";
    public string Description => "NTFS USN change journal (file create/rename/delete history)";

    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
    private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint OPEN_EXISTING = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct READ_USN_JOURNAL_DATA_V0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
        ref USN_JOURNAL_DATA_V0 lpInBuffer, int nInBufferSize,
        out USN_JOURNAL_DATA_V0 lpOutBuffer, int nOutBufferSize,
        out int lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
        ref READ_USN_JOURNAL_DATA_V0 lpInBuffer, int nInBufferSize,
        IntPtr lpOutBuffer, int nOutBufferSize,
        out int lpBytesReturned, IntPtr lpOverlapped);

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "usn");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Fixed || drive.DriveFormat != "NTFS") continue;

            var letter = drive.Name.TrimEnd('\\').TrimEnd(':');
            try
            {
                int records = ReadUsnVolume(letter, Path.Combine(destDir, $"{letter}_usnjrnl.jsonl"));
                if (records > 0)
                {
                    var dest = Path.Combine(destDir, $"{letter}_usnjrnl.jsonl");
                    var size = new FileInfo(dest).Length;
                    context.CollectedFiles.Add(new CollectedFileEntry
                    {
                        OriginalPath = $"\\\\.\\{letter}:\\$Extend\\$UsnJrnl:$J",
                        RelativePath = Path.GetRelativePath(context.OutputDir, dest).Replace('\\', '/'),
                        Category = "usn_journal",
                        Size = size
                    });
                    count++;
                    bytes += size;
                    ConsoleOutput.Status($"  {letter}:: {records} USN records");
                }
            }
            catch (Exception ex)
            {
                ConsoleOutput.Warning($"  {letter}: USN read failed: {ex.Message}");
            }
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = bytes,
            Elapsed = sw.Elapsed
        };
    }

    private static int ReadUsnVolume(string driveLetter, string destPath)
    {
        using var h = CreateFile($"\\\\.\\{driveLetter}:", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return 0;

        var queryIn = new USN_JOURNAL_DATA_V0();
        if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, ref queryIn, 0,
                out var journal, Marshal.SizeOf<USN_JOURNAL_DATA_V0>(), out _, IntPtr.Zero))
        {
            return 0;
        }

        var read = new READ_USN_JOURNAL_DATA_V0
        {
            StartUsn = journal.LowestValidUsn,
            ReasonMask = 0xFFFFFFFF,
            ReturnOnlyOnClose = 0,
            Timeout = 0,
            BytesToWaitFor = 0,
            UsnJournalID = journal.UsnJournalID
        };

        const int bufferSize = 1024 * 1024;
        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            using var fs = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024);
            using var sw = new StreamWriter(fs);
            int totalRecords = 0;

            while (true)
            {
                if (!DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, ref read, Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>(),
                    buffer, bufferSize, out var bytesReturned, IntPtr.Zero))
                {
                    break;
                }

                if (bytesReturned <= sizeof(long)) break;

                long nextUsn = Marshal.ReadInt64(buffer);
                int offset = sizeof(long);

                while (offset < bytesReturned)
                {
                    var recordPtr = IntPtr.Add(buffer, offset);
                    int recordLen = Marshal.ReadInt32(recordPtr);
                    if (recordLen == 0 || offset + recordLen > bytesReturned) break;

                    int majorVersion = Marshal.ReadInt16(recordPtr, 4);
                    if (majorVersion >= 2 && majorVersion <= 3)
                    {
                        long usn = Marshal.ReadInt64(recordPtr, 8);
                        long timestamp = Marshal.ReadInt64(recordPtr, 32);
                        uint reason = (uint)Marshal.ReadInt32(recordPtr, 40);
                        uint sourceInfo = (uint)Marshal.ReadInt32(recordPtr, 44);
                        uint fileAttributes = (uint)Marshal.ReadInt32(recordPtr, 52);
                        short fileNameLength = Marshal.ReadInt16(recordPtr, 56);
                        short fileNameOffset = Marshal.ReadInt16(recordPtr, 58);
                        var fileName = Marshal.PtrToStringUni(IntPtr.Add(recordPtr, fileNameOffset),
                            fileNameLength / 2);

                        sw.WriteLine(JsonSerializer.Serialize(new
                        {
                            usn,
                            timestamp = DateTime.FromFileTimeUtc(timestamp).ToString("o"),
                            reason = reason.ToString("X"),
                            source_info = sourceInfo,
                            file_attributes = fileAttributes,
                            file_name = fileName
                        }));
                        totalRecords++;
                    }

                    offset += recordLen;
                }

                if (nextUsn == read.StartUsn) break;
                read.StartUsn = nextUsn;

                // Cap to avoid filling disk on huge journals
                if (totalRecords > 5_000_000) break;
            }

            return totalRecords;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
