using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class LnkCollector : ICollector
{
    public string Name => "LnkFiles";
    public string Description => "Shortcut (.lnk) files from user Recent folders";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "lnk");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            var recentDir = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Recent");

            if (!Directory.Exists(recentDir)) continue;

            foreach (var file in Directory.EnumerateFiles(recentDir, "*.lnk"))
            {
                try
                {
                    var dest = Path.Combine(destDir, $"{username}_{Path.GetFileName(file)}");
                    File.Copy(file, dest, overwrite: true);
                    var size = new FileInfo(dest).Length;
                    context.CollectedFiles.Add(new CollectedFileEntry
                    {
                        OriginalPath = file,
                        RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                        Category = "lnk",
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
