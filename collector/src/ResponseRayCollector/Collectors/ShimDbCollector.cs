using System.Diagnostics;

namespace ResponseRayCollector.Collectors;

public class ShimDbCollector : ICollector
{
    public string Name => "ShimDB";
    public string Description => "Custom application compatibility shim databases (.sdb)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        var dirs = new[]
        {
            @"C:\Windows\AppPatch\Custom",
            @"C:\Windows\AppPatch\Custom\Custom64",
            @"C:\Windows\apppatch",
        };

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*.sdb", SearchOption.AllDirectories))
            {
                var relPath = Path.GetRelativePath(dir, file);
                var rel = Path.Combine("artifacts", "shimdb", Path.GetFileName(dir), relPath);
                context.TryCaptureFile(file, rel, "shim_db", ref count, ref bytes);
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
