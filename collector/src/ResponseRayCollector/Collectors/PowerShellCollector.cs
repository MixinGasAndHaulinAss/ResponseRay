using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class PowerShellCollector : ICollector
{
    public string Name => "PowerShellHistory";
    public string Description => "PowerShell ConsoleHost_history.txt per user";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "powershell");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            var historyPath = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

            if (!File.Exists(historyPath)) continue;

            try
            {
                var dest = Path.Combine(destDir, $"{username}_ConsoleHost_history.txt");
                File.Copy(historyPath, dest, overwrite: true);
                var size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = historyPath,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "powershell",
                    Size = size
                });
                count++;
                bytes += size;
            }
            catch { /* skip inaccessible */ }
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
