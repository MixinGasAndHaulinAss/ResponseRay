using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class IconThumbCacheCollector : ICollector
{
    public string Name => "IconThumbCache";
    public string Description => "Per-user iconcache_*.db and thumbcache_*.db";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            var explorerDir = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Windows", "Explorer");
            if (!Directory.Exists(explorerDir)) continue;

            foreach (var file in Directory.EnumerateFiles(explorerDir, "*cache_*.db"))
            {
                var rel = Path.Combine("artifacts", "iconthumbcache", username, Path.GetFileName(file));
                context.TryCaptureFile(file, rel, "iconthumb_cache", ref count, ref bytes);
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
