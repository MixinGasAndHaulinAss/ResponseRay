using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class PrefetchCollector : ICollector
{
    public string Name => "Prefetch";
    public string Description => "Windows Prefetch files (.pf)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "prefetch");
        Directory.CreateDirectory(destDir);

        var prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetchDir))
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        int count = FileHelper.CopyDirectory(prefetchDir, destDir, "*.pf");
        long bytes = FileHelper.GetDirectorySize(destDir);

        foreach (var file in Directory.EnumerateFiles(destDir, "*.pf"))
        {
            var originalPath = Path.Combine(prefetchDir, Path.GetFileName(file));
            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = originalPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, file),
                Category = "prefetch",
                Size = new FileInfo(file).Length
            });
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
