using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class StartupItemCollector : ICollector
{
    public string Name => "StartupItems";
    public string Description => "Autostart entries: Run/RunOnce keys, Startup folders, shell extensions, COM objects, browser extensions, WMI subscriptions";

    private static readonly string[] HklmRunPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ];

    private static readonly string[] HkuRunPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var items = new List<StartupItemInfo>();

        // HKLM autostart keys
        foreach (var path in HklmRunPaths)
            CollectFromRegistry(Registry.LocalMachine, path, "HKLM", "SYSTEM", items, timestamp);

        // Per-user HKU autostart keys
        try
        {
            using var hku = Registry.Users;
            foreach (var sid in hku.GetSubKeyNames())
            {
                foreach (var regPath in HkuRunPaths)
                    CollectFromRegistry(hku, $@"{sid}\{regPath}", $@"HKU\{sid}", sid, items, timestamp);
            }
        }
        catch { }

        // Shell extensions (HKLM)
        CollectShellExtensions(items, timestamp);

        // Browser extensions
        CollectBrowserExtensions(items, timestamp);

        // WMI event subscriptions
        CollectWmiSubscriptions(items, timestamp);

        // Image File Execution Options (debugger hijacks)
        CollectIfeoDebuggers(items, timestamp);

        // AppInit_DLLs
        CollectAppInitDlls(items, timestamp);

        // Startup folders
        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            var startupDir = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows",
                "Start Menu", "Programs", "Startup");
            if (!Directory.Exists(startupDir)) continue;

            foreach (var file in Directory.EnumerateFiles(startupDir))
            {
                items.Add(new StartupItemInfo
                {
                    Name = Path.GetFileName(file),
                    Command = file,
                    Location = "Startup Folder",
                    User = username,
                    CollectionTimestamp = timestamp
                });
            }
        }

        var commonStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            "Programs", "Startup");
        if (Directory.Exists(commonStartup))
        {
            foreach (var file in Directory.EnumerateFiles(commonStartup))
            {
                items.Add(new StartupItemInfo
                {
                    Name = Path.GetFileName(file),
                    Command = file,
                    Location = "Common Startup Folder",
                    User = "All Users",
                    CollectionTimestamp = timestamp
                });
            }
        }

        var dest = Path.Combine(destDir, "startup_items.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = items.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void CollectShellExtensions(List<StartupItemInfo> items, string timestamp)
    {
        var shellPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            @"SOFTWARE\Classes\CLSID",
        };

        foreach (var path in shellPaths.Take(3)) // Skip CLSID full enum
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;
                foreach (var name in key.GetSubKeyNames().Take(200)) // cap to avoid massive output
                {
                    var value = "";
                    try
                    {
                        using var sub = key.OpenSubKey(name);
                        value = sub?.GetValue("")?.ToString() ?? "";
                    }
                    catch { }

                    items.Add(new StartupItemInfo
                    {
                        Name = name,
                        Command = value,
                        Location = $@"HKLM\{path}",
                        User = "SYSTEM",
                        CollectionTimestamp = timestamp
                    });
                }
            }
            catch { }
        }
    }

    private static void CollectBrowserExtensions(List<StartupItemInfo> items, string timestamp)
    {
        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;

            // Chrome extensions
            var chromeExtDir = Path.Combine(userDir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions");
            CollectExtensionDir(chromeExtDir, "Chrome", username, items, timestamp);

            // Edge extensions
            var edgeExtDir = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Extensions");
            CollectExtensionDir(edgeExtDir, "Edge", username, items, timestamp);
        }
    }

    private static void CollectExtensionDir(string extDir, string browser, string username,
        List<StartupItemInfo> items, string timestamp)
    {
        if (!Directory.Exists(extDir)) return;

        foreach (var extFolder in Directory.EnumerateDirectories(extDir))
        {
            var extId = Path.GetFileName(extFolder);
            var extName = extId;

            // Try to read manifest.json for display name
            foreach (var versionDir in Directory.EnumerateDirectories(extFolder))
            {
                var manifestPath = Path.Combine(versionDir, "manifest.json");
                if (!File.Exists(manifestPath)) continue;
                try
                {
                    var json = File.ReadAllText(manifestPath);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("name", out var nameProp))
                    {
                        var n = nameProp.GetString() ?? "";
                        if (!n.StartsWith("__MSG_")) extName = n;
                    }
                }
                catch { }
                break;
            }

            items.Add(new StartupItemInfo
            {
                Name = extName,
                Command = extId,
                Location = $"{browser} Extension",
                User = username,
                CollectionTimestamp = timestamp
            });
        }
    }

    private static void CollectWmiSubscriptions(List<StartupItemInfo> items, string timestamp)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\subscription", "SELECT * FROM __EventConsumer");
            foreach (var obj in searcher.Get())
            {
                items.Add(new StartupItemInfo
                {
                    Name = obj["Name"]?.ToString() ?? "WMI Consumer",
                    Command = obj["CommandLineTemplate"]?.ToString() ?? obj["ScriptText"]?.ToString() ?? "",
                    Location = "WMI EventConsumer",
                    User = "SYSTEM",
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch { }

        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\subscription", "SELECT * FROM __EventFilter");
            foreach (var obj in searcher.Get())
            {
                items.Add(new StartupItemInfo
                {
                    Name = obj["Name"]?.ToString() ?? "WMI Filter",
                    Command = obj["Query"]?.ToString() ?? "",
                    Location = "WMI EventFilter",
                    User = "SYSTEM",
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch { }
    }

    private static void CollectIfeoDebuggers(List<StartupItemInfo> items, string timestamp)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (key == null) return;

            foreach (var name in key.GetSubKeyNames())
            {
                using var sub = key.OpenSubKey(name);
                var debugger = sub?.GetValue("Debugger")?.ToString();
                if (!string.IsNullOrEmpty(debugger))
                {
                    items.Add(new StartupItemInfo
                    {
                        Name = name,
                        Command = debugger,
                        Location = "IFEO Debugger",
                        User = "SYSTEM",
                        CollectionTimestamp = timestamp
                    });
                }
            }
        }
        catch { }
    }

    private static void CollectAppInitDlls(List<StartupItemInfo> items, string timestamp)
    {
        foreach (var path in new[] {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                var value = key?.GetValue("AppInit_DLLs")?.ToString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    items.Add(new StartupItemInfo
                    {
                        Name = "AppInit_DLLs",
                        Command = value,
                        Location = $@"HKLM\{path}",
                        User = "SYSTEM",
                        CollectionTimestamp = timestamp
                    });
                }
            }
            catch { }
        }
    }

    private static void CollectFromRegistry(RegistryKey root, string path, string locationPrefix,
        string user, List<StartupItemInfo> items, string timestamp)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) return;

            foreach (var name in key.GetValueNames())
            {
                var value = key.GetValue(name)?.ToString() ?? "";
                items.Add(new StartupItemInfo
                {
                    Name = name,
                    Command = value,
                    Location = $@"{locationPrefix}\{path}",
                    User = user,
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch { }
    }
}
