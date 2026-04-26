using System.Diagnostics;

namespace ResponseRayCollector.Collectors;

public class DefenderLogCollector : ICollector
{
    public string Name => "DefenderLogs";
    public string Description => "Windows Defender platform logs, MpEnginedb.db, MPLog files, scan history";

    private const long MaxFileSize = 200L * 1024 * 1024;

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        var roots = new[]
        {
            @"C:\ProgramData\Microsoft\Windows Defender\Support",
            @"C:\ProgramData\Microsoft\Windows Defender\Scans\History",
            @"C:\ProgramData\Microsoft\Windows Defender\Network Inspection System\Support",
        };

        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                try
                {
                    if (new FileInfo(file).Length > MaxFileSize) continue;
                    var relPath = Path.GetRelativePath(root, file);
                    var rel = Path.Combine("artifacts", "defender", Path.GetFileName(root), relPath);
                    context.TryCaptureFile(file, rel, "defender", ref count, ref bytes);
                }
                catch { }
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
