using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Captures the first 512 bytes (MBR / protective MBR) of each physical disk (\\.\PhysicalDriveN).
/// Useful for detecting bootkits and validating partition table integrity.
/// </summary>
public class MbrCollector : ICollector
{
    public string Name => "MBR";
    public string Description => "Master Boot Record (first sector) of every physical disk";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "mbr");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        for (int i = 0; i < 16; i++)
        {
            var device = $"\\\\.\\PhysicalDrive{i}";
            try
            {
                using var h = CreateFile(device, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (h.IsInvalid) continue;
                using var stream = new FileStream(h, FileAccess.Read, 512);
                var buffer = new byte[512];
                int read = stream.Read(buffer, 0, 512);
                if (read != 512) continue;

                var dest = Path.Combine(destDir, $"PhysicalDrive{i}.mbr");
                File.WriteAllBytes(dest, buffer);
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = device,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest).Replace('\\', '/'),
                    Category = "mbr",
                    Size = read
                });
                count++;
                bytes += read;
            }
            catch
            {
                // No more disks at this index
                break;
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
}
