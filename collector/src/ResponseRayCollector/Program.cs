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
        var noVss = HasFlag(args, "--no-vss");
        var includeMemory = HasFlag(args, "--include-memory");

        var hostname = Environment.MachineName;
        var timestamp = DateTime.Now;
        var collectionDir = Path.Combine(Path.GetTempPath(), $"ResponseRay_{hostname}_{timestamp:yyyyMMdd_HHmmss}");

        ConsoleOutput.Info($"Hostname: {hostname}");
        ConsoleOutput.Info($"Output:   {outputPath}");
        if (skipList.Count > 0)
            ConsoleOutput.Info($"Skipping: {string.Join(", ", skipList)}");
        if (noVss)
            ConsoleOutput.Info("VSS:      disabled (--no-vss)");
        if (includeMemory)
            ConsoleOutput.Info("Memory:   included (--include-memory)");

        Directory.CreateDirectory(collectionDir);
        var overallSw = Stopwatch.StartNew();

        var context = new CollectionContext
        {
            OutputDir = collectionDir,
            Hostname = hostname,
            CollectionTime = timestamp,
            IncludeMemory = includeMemory
        };

        FileHelper.EnablePrivilege("SeBackupPrivilege");
        FileHelper.EnablePrivilege("SeManageVolumePrivilege");
        FileHelper.EnablePrivilege("SeRestorePrivilege");
        FileHelper.EnablePrivilege("SeSecurityPrivilege");

        // Try to create a VSS snapshot of the system drive so collectors can read locked files cleanly.
        VssManager? vss = null;
        if (!noVss)
        {
            vss = new VssManager();
            var systemDrive = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 3);
            if (vss.CreateSnapshot(systemDrive))
            {
                context.VssShadowPath = vss.ShadowPath;
            }
            else
            {
                ConsoleOutput.Warning("VSS snapshot unavailable; falling back to live filesystem with backup-semantics copy.");
                vss.Dispose();
                vss = null;
            }
        }

        ICollector[] collectors =
        [
            new EventLogCollector(),
            new RegistryCollector(),
            new RegBackCollector(),
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
            new NtfsMetafilesCollector(),
            new MbrCollector(),
            new UsnJournalCollector(),
            new HostsCollector(),
            new EventTranscriptCollector(),
            new RdpCacheCollector(),
            new QuickAssistCollector(),
            new CrashDumpCollector(),
            new IconThumbCacheCollector(),
            new EtlLogCollector(),
            new ShimDbCollector(),
            new WerFileCollector(),
            new DefenderLogCollector(),
            new NtdsCollector(),
            new ApplicationLogsCollector(),
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
            new DriverCollector(),
            new AntivirusCollector(),
            new InstalledAppsCollector(),
            new NetworkAdapterCollector(),
            new NetworkShareCollector(),
            new WirelessHistoryCollector(),
            new FirewallRulesCollector(),
            new VolumeShadowCopyCollector(),
            new VolumeInfoCollector(),
            new RestorePointCollector(),
            new EnvVarCollector(),
            new DefaultBrowserCollector(),
            new ProxyCollector(),
            new DnsServerCollector(),
            new ZoneIdentifierCollector(),
            new StoreAppCollector(),
            new MemoryArtifactCollector(),
            new FileSystemCollector(),
        ];

        var manifest = new CollectionManifest
        {
            CollectorVersion = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            Platform = "windows",
            Hostname = hostname,
            OsVersion = Environment.OSVersion.ToString(),
            Domain = Environment.UserDomainName,
            CollectionTimestamp = timestamp.ToUniversalTime().ToString("o"),
            VssUsed = context.VssShadowPath != null,
            VssPath = context.VssShadowPath,
            UserProfiles = FileHelper.GetUserProfilePaths().Select(Path.GetFileName).Where(n => n != null).Cast<string>().ToList()
        };

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

        // Tear down the snapshot before zipping to release resources.
        vss?.Dispose();

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

    private static bool HasFlag(string[] args, string name)
    {
        return args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
    }
}
