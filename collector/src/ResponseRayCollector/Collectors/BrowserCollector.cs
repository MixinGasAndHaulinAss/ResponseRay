using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class BrowserCollector : ICollector
{
    public string Name => "Browser";
    public string Description => "Chrome, Edge, and Firefox browser history databases";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "browser");
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;

            // Chrome profiles
            CollectBrowserProfiles(context, userDir, username,
                Path.Combine("AppData", "Local", "Google", "Chrome", "User Data"),
                "chrome", destDir, ref count, ref bytes);

            // Edge profiles
            CollectBrowserProfiles(context, userDir, username,
                Path.Combine("AppData", "Local", "Microsoft", "Edge", "User Data"),
                "edge", destDir, ref count, ref bytes);

            // Firefox profiles
            var ffProfilesDir = Path.Combine(userDir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
            var ffSrc = !string.IsNullOrEmpty(context.VssRoot)
                ? FileHelper.ResolveVssPath(context.VssRoot, ffProfilesDir) : ffProfilesDir;

            if (Directory.Exists(ffSrc))
            {
                foreach (var profileDir in Directory.EnumerateDirectories(ffSrc))
                {
                    var profileName = Path.GetFileName(profileDir);
                    var placesPath = Path.Combine(profileDir, "places.sqlite");
                    if (!File.Exists(placesPath)) continue;

                    try
                    {
                        var dest = Path.Combine(destDir, "firefox", $"{username}_{profileName}_places.sqlite");
                        FileHelper.SafeCopy(placesPath, dest);
                        var size = new FileInfo(dest).Length;
                        context.CollectedFiles.Add(new CollectedFileEntry
                        {
                            OriginalPath = Path.Combine(ffProfilesDir, profileName, "places.sqlite"),
                            RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                            Category = "browser",
                            Size = size
                        });
                        count++;
                        bytes += size;
                    }
                    catch { /* skip inaccessible */ }
                }
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

    private static void CollectBrowserProfiles(CollectionContext context, string userDir, string username,
        string relBrowserPath, string browserName, string destDir, ref int count, ref long bytes)
    {
        var browserDir = Path.Combine(userDir, relBrowserPath);
        var src = !string.IsNullOrEmpty(context.VssRoot)
            ? FileHelper.ResolveVssPath(context.VssRoot, browserDir) : browserDir;

        if (!Directory.Exists(src)) return;

        // Check Default profile and numbered profiles
        foreach (var profileDir in Directory.EnumerateDirectories(src).Append(src))
        {
            var historyPath = Path.Combine(profileDir, "History");
            if (!File.Exists(historyPath)) continue;

            var profileName = Path.GetFileName(profileDir);
            if (profileName == Path.GetFileName(src))
                profileName = "Default";

            try
            {
                var dest = Path.Combine(destDir, browserName, $"{username}_{profileName}_History");
                FileHelper.SafeCopy(historyPath, dest);
                var size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = Path.Combine(browserDir, profileName, "History"),
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "browser",
                    Size = size
                });
                count++;
                bytes += size;
            }
            catch { /* skip inaccessible */ }
        }
    }
}
