using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class QuickAssistCollector : ICollector
{
    public string Name => "QuickAssist";
    public string Description => "Quick Assist (msra) cached state and remote-assistance saved sessions";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;

            string[] candidatePaths =
            [
                Path.Combine(userDir, "AppData", "Local", "Packages",
                    "MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe"),
                Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "MSRA"),
            ];

            foreach (var root in candidatePaths)
            {
                if (!Directory.Exists(root)) continue;

                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var info = new FileInfo(file);
                        if (info.Length > 100 * 1024 * 1024) continue;
                        var relPath = Path.GetRelativePath(root, file);
                        var rel = Path.Combine("artifacts", "quickassist", username, relPath);
                        context.TryCaptureFile(file, rel, "quick_assist", ref count, ref bytes);
                    }
                    catch { }
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
}
