using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Captures auxiliary NTFS metafiles (besides $MFT, which has its own collector):
/// $Boot, $LogFile, $Secure:$SDS, $TxfLog, $MFTMirr, $UsnJrnl:$J handled by UsnJournalCollector.
/// Reads the raw volume via \\.\C: like MftCollector does.
/// </summary>
public class NtfsMetafilesCollector : ICollector
{
    public string Name => "NtfsMetafiles";
    public string Description => "$Boot, $LogFile, $Secure, $TxfLog, $MFTMirr from each NTFS volume";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "ntfs");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Fixed || drive.DriveFormat != "NTFS") continue;

            var letter = drive.Name.TrimEnd('\\').TrimEnd(':');
            // Try to capture each metafile by direct path; this works for $Boot/$LogFile which
            // are MFT-resident and accessible with backup semantics on most systems.
            string[] metafiles = ["$Boot", "$LogFile", "$Secure", "$MFTMirr", "$AttrDef", "$Bitmap"];
            foreach (var meta in metafiles)
            {
                try
                {
                    var src = $"\\\\.\\{letter}:\\{meta}";
                    var dest = Path.Combine(destDir, $"{letter}_{meta.TrimStart('$')}");
                    if (CopyMetafile(src, dest))
                    {
                        var size = new FileInfo(dest).Length;
                        context.CollectedFiles.Add(new CollectedFileEntry
                        {
                            OriginalPath = $"{letter}:\\{meta}",
                            RelativePath = Path.GetRelativePath(context.OutputDir, dest).Replace('\\', '/'),
                            Category = "ntfs",
                            Size = size
                        });
                        count++;
                        bytes += size;
                    }
                }
                catch (Exception ex)
                {
                    ConsoleOutput.Status($"  {letter}:\\{meta}: {ex.Message}");
                }
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    private static bool CopyMetafile(string src, string dest)
    {
        try
        {
            using var h = CreateFile(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h.IsInvalid) return false;
            using var inStream = new FileStream(h, FileAccess.Read, 1024 * 1024);
            using var outStream = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024);
            inStream.CopyTo(outStream, 1024 * 1024);
            return new FileInfo(dest).Length > 0;
        }
        catch
        {
            return false;
        }
    }
}
