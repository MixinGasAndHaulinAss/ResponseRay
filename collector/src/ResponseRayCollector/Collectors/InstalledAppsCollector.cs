using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace ResponseRayCollector.Collectors;

public class InstalledAppsCollector : ICollector
{
    public string Name => "InstalledApps";
    public string Description => "Installed applications from HKLM/HKU Uninstall registry keys";

    private static readonly string[] UninstallKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var apps = new List<Dictionary<string, object?>>();

        foreach (var path in UninstallKeys)
        {
            CollectFrom(Registry.LocalMachine, path, "HKLM", apps, timestamp);
        }

        try
        {
            using var hku = Registry.Users;
            foreach (var sid in hku.GetSubKeyNames())
            {
                if (sid.StartsWith("S-1-5-21-"))
                {
                    foreach (var key in UninstallKeys)
                        CollectFrom(hku, $@"{sid}\{key}", $@"HKU\{sid}", apps, timestamp);
                }
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "installed_apps.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(apps, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = apps.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void CollectFrom(RegistryKey root, string path, string label,
        List<Dictionary<string, object?>> apps, string timestamp)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) return;
            foreach (var name in key.GetSubKeyNames())
            {
                using var sub = key.OpenSubKey(name);
                if (sub == null) continue;
                var displayName = sub.GetValue("DisplayName")?.ToString();
                if (string.IsNullOrEmpty(displayName)) continue;

                apps.Add(new Dictionary<string, object?>
                {
                    ["registry_location"] = $@"{label}\{path}\{name}",
                    ["display_name"] = displayName,
                    ["display_version"] = sub.GetValue("DisplayVersion")?.ToString(),
                    ["publisher"] = sub.GetValue("Publisher")?.ToString(),
                    ["install_date"] = sub.GetValue("InstallDate")?.ToString(),
                    ["install_location"] = sub.GetValue("InstallLocation")?.ToString(),
                    ["install_source"] = sub.GetValue("InstallSource")?.ToString(),
                    ["uninstall_string"] = sub.GetValue("UninstallString")?.ToString(),
                    ["estimated_size_kb"] = sub.GetValue("EstimatedSize"),
                    ["collection_timestamp"] = timestamp
                });
            }
        }
        catch { }
    }
}
