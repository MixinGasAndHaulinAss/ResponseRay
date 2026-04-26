using System.Diagnostics;

namespace ResponseRayCollector.Collectors;

public class RegBackCollector : ICollector
{
    public string Name => "RegBack";
    public string Description => "Old registry hive backups from %SystemRoot%\\System32\\config\\RegBack";

    private static readonly string[] Hives = ["SAM", "SECURITY", "SOFTWARE", "SYSTEM", "DEFAULT"];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var regBackDir = Path.Combine(win, "System32", "config", "RegBack");
        int count = 0;
        long bytes = 0;

        foreach (var hive in Hives)
        {
            var src = Path.Combine(regBackDir, hive);
            var rel = Path.Combine("artifacts", "registry", "RegBack", hive);
            context.TryCaptureFile(src, rel, "registry", ref count, ref bytes);
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
