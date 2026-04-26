using System.Diagnostics;

namespace ResponseRayCollector.Collectors;

public class EtlLogCollector : ICollector
{
    public string Name => "EtlLogs";
    public string Description => "Forensically interesting ETL files (boot trace, WMI, Windows Update, AppCompat)";

    private static readonly string[] EtlGlobs =
    [
        @"C:\Windows\System32\WDI\LogFiles",
        @"C:\Windows\Logs\WindowsUpdate",
        @"C:\Windows\Performance\WinSAT",
        @"C:\Windows\Logs\AppCompat",
        @"C:\Windows\System32\Sru",
        @"C:\Windows\System32\LogFiles\Sum",
    ];

    private const long MaxFileSize = 200L * 1024 * 1024;

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        foreach (var root in EtlGlobs)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var file in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories))
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is not (".etl" or ".log" or ".dat" or ".jrs" or ".chk" or ".mdb")) continue;
                try
                {
                    if (new FileInfo(file).Length > MaxFileSize) continue;
                }
                catch { continue; }

                var relPath = Path.GetRelativePath(root, file);
                var rel = Path.Combine("artifacts", "etl", Path.GetFileName(root), relPath);
                context.TryCaptureFile(file, rel, "etl", ref count, ref bytes);
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
}
