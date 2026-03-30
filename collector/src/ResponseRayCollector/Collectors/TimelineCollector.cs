using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class TimelineCollector : ICollector
{
    public string Name => "WindowsTimeline";
    public string Description => "Windows Timeline (ActivitiesCache.db) per user";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "timeline");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            var cdpDir = Path.Combine(userDir, "AppData", "Local", "ConnectedDevicesPlatform");

            // Resolve via VSS if available (database may be locked)
            var srcCdpDir = !string.IsNullOrEmpty(context.VssRoot)
                ? FileHelper.ResolveVssPath(context.VssRoot, cdpDir) : cdpDir;

            if (!Directory.Exists(srcCdpDir)) continue;

            foreach (var subDir in Directory.EnumerateDirectories(srcCdpDir))
            {
                var dbPath = Path.Combine(subDir, "ActivitiesCache.db");
                if (!File.Exists(dbPath)) continue;

                try
                {
                    var subDirName = Path.GetFileName(subDir);
                    var dest = Path.Combine(destDir, $"{username}_{subDirName}_ActivitiesCache.db");
                    File.Copy(dbPath, dest, overwrite: true);
                    var size = new FileInfo(dest).Length;
                    context.CollectedFiles.Add(new CollectedFileEntry
                    {
                        OriginalPath = Path.Combine(cdpDir, subDirName, "ActivitiesCache.db"),
                        RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                        Category = "timeline",
                        Size = size
                    });
                    count++;
                    bytes += size;
                }
                catch { /* skip inaccessible */ }
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
