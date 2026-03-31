using System.Diagnostics;
using System.IO.Compression;
using System.Security.Principal;
using ResponseRayCollector.Collectors;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector;

public static class Program
{
    public static int Main(string[] args)
    {
        ConsoleOutput.Banner();

        if (!IsAdministrator())
        {
            ConsoleOutput.Error("This tool must be run as Administrator.");
            ConsoleOutput.Error("Right-click and select 'Run as administrator', or use an elevated command prompt.");
            return 1;
        }

        var outputPath = ParseArg(args, "--output") ?? Directory.GetCurrentDirectory();
        var skipList = (ParseArg(args, "--skip") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim().ToLowerInvariant()).ToHashSet();

        var hostname = Environment.MachineName;
        var timestamp = DateTime.Now;
        var collectionDir = Path.Combine(Path.GetTempPath(), $"ResponseRay_{hostname}_{timestamp:yyyyMMdd_HHmmss}");

        ConsoleOutput.Info($"Hostname: {hostname}");
        ConsoleOutput.Info($"Output:   {outputPath}");
        if (skipList.Count > 0)
            ConsoleOutput.Info($"Skipping: {string.Join(", ", skipList)}");

        Directory.CreateDirectory(collectionDir);
        var overallSw = Stopwatch.StartNew();

        var context = new CollectionContext
        {
            OutputDir = collectionDir,
            Hostname = hostname,
            CollectionTime = timestamp
        };

        ICollector[] collectors =
        [
            new EventLogCollector(),
            new RegistryCollector(),
            new PrefetchCollector(),
            new SrumCollector(),
            new BrowserCollector(),
            new TimelineCollector(),
            new WmiCollector(),
            new RecycleBinCollector(),
            new TaskCollector(),
            new PowerShellCollector(),
            new LnkCollector(),
            new DhcpCollector(),
            new MftCollector(),
            new ProcessCollector(),
            new NetworkCollector(),
            new DnsCacheCollector(),
            new ArpCacheCollector(),
            new RoutingTableCollector(),
            new LogonSessionCollector(),
            new UserAccountCollector(),
            new ServiceCollector(),
            new StartupItemCollector(),
            new DeviceCollector(),
            new UserAccessedDataCollector(),
            new OsConfigCollector(),
            new FileSystemCollector(),
        ];

        var manifest = new CollectionManifest
        {
            CollectorVersion = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            Hostname = hostname,
            OsVersion = Environment.OSVersion.ToString(),
            Domain = Environment.UserDomainName,
            CollectionTimestamp = timestamp.ToUniversalTime().ToString("o"),
            UserProfiles = FileHelper.GetUserProfilePaths().Select(Path.GetFileName).Where(n => n != null).Cast<string>().ToList()
        };

        FileHelper.EnablePrivilege("SeBackupPrivilege");
        FileHelper.EnablePrivilege("SeManageVolumePrivilege");

        ConsoleOutput.Section("Collecting Artifacts");

        foreach (var collector in collectors)
        {
            if (skipList.Contains(collector.Name.ToLowerInvariant()))
            {
                ConsoleOutput.Status($"Skipping {collector.Name}");
                continue;
            }

            try
            {
                var result = collector.Collect(context);
                manifest.CollectorResults.Add(new CollectionManifest.CollectorResultEntry
                {
                    Name = result.CollectorName,
                    FilesCollected = result.FilesCollected,
                    BytesCollected = result.BytesCollected,
                    ElapsedMs = (long)result.Elapsed.TotalMilliseconds,
                    Error = result.Error
                });

                if (result.Error != null)
                    ConsoleOutput.Warning($"{collector.Name}: {result.Error}");
                else if (result.FilesCollected > 0)
                    ConsoleOutput.Info($"{collector.Name}: {result.FilesCollected} files ({FileHelper.FormatSize(result.BytesCollected)}) in {result.Elapsed.TotalSeconds:F1}s");
                else
                    ConsoleOutput.Status($"{collector.Name}: nothing found");
            }
            catch (Exception ex)
            {
                ConsoleOutput.Error($"{collector.Name} failed: {ex.Message}");
                manifest.CollectorResults.Add(new CollectionManifest.CollectorResultEntry
                {
                    Name = collector.Name,
                    Error = ex.Message
                });
            }
        }

        foreach (var entry in context.CollectedFiles)
        {
            manifest.Files.Add(new CollectionManifest.FileEntry
            {
                OriginalPath = entry.OriginalPath,
                RelativePath = entry.RelativePath,
                Category = entry.Category,
                Size = entry.Size
            });
        }

        manifest.TotalFiles = manifest.Files.Count;
        manifest.TotalBytes = FileHelper.GetDirectorySize(collectionDir);
        manifest.CollectionDurationSeconds = overallSw.Elapsed.TotalSeconds;

        var manifestPath = Path.Combine(collectionDir, "manifest.json");
        manifest.Save(manifestPath);

        ConsoleOutput.Section("Packaging");
        var zipName = $"{hostname}_{timestamp:yyyyMMdd_HHmmss}.zip";
        var zipPath = Path.Combine(outputPath, zipName);

        ConsoleOutput.Info($"Creating {zipName}...");
        if (File.Exists(zipPath))
            File.Delete(zipPath);
        ZipFile.CreateFromDirectory(collectionDir, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);

        var zipSize = new FileInfo(zipPath).Length;
        overallSw.Stop();

        try { Directory.Delete(collectionDir, recursive: true); }
        catch { /* best effort */ }

        ConsoleOutput.Section("Collection Complete");
        ConsoleOutput.Info($"Output:   {zipPath}");
        ConsoleOutput.Info($"Size:     {FileHelper.FormatSize(zipSize)}");
        ConsoleOutput.Info($"Files:    {manifest.TotalFiles}");
        ConsoleOutput.Info($"Duration: {overallSw.Elapsed.TotalSeconds:F1}s");
        Console.WriteLine();

        return 0;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? ParseArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return null;
    }
}
