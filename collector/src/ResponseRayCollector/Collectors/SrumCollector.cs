using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class SrumCollector : ICollector
{
    public string Name => "SRUM";
    public string Description => "SRUM database (SRUDB.dat)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "srum");
        Directory.CreateDirectory(destDir);

        var originalPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "SRU", "SRUDB.dat");
        var source = originalPath;

        if (!string.IsNullOrEmpty(context.VssRoot))
        {
            var vssPath = FileHelper.ResolveVssPath(context.VssRoot, originalPath);
            if (File.Exists(vssPath))
                source = vssPath;
        }

        if (!File.Exists(source))
        {
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };
        }

        try
        {
            var dest = Path.Combine(destDir, "SRUDB.dat");
            FileHelper.SafeCopy(source, dest);
            var size = new FileInfo(dest).Length;
            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = originalPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                Category = "srum",
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
        catch (Exception ex)
        {
            return new CollectorResult { CollectorName = Name, Error = ex.Message, Elapsed = sw.Elapsed };
        }
    }
}
