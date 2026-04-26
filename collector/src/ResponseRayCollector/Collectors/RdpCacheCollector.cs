using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class RdpCacheCollector : ICollector
{
    public string Name => "RdpCache";
    public string Description => "Per-user RDP bitmap cache (Cache0000.bin / bcache*.bmc)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            var cacheDir = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache");
            if (!Directory.Exists(cacheDir)) continue;

            foreach (var file in Directory.EnumerateFiles(cacheDir))
            {
                var rel = Path.Combine("artifacts", "rdp_cache", username, Path.GetFileName(file));
                context.TryCaptureFile(file, rel, "rdp_cache", ref count, ref bytes);
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
