using System.Diagnostics;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class StoreAppCollector : ICollector
{
    public string Name => "StoreApps";
    public string Description => "Microsoft Store / UWP apps via Get-AppxPackage";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var apps = new List<Dictionary<string, object?>>();
        try
        {
            var psScript = "Get-AppxPackage -AllUsers | Select Name, PackageFullName, PackageFamilyName, Publisher, Version, Architecture, InstallLocation, IsFramework, IsResourcePackage, SignatureKind, Status | ConvertTo-Json -Depth 3 -Compress";
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -Command \"{psScript}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(120_000);

                if (!string.IsNullOrWhiteSpace(output))
                {
                    using var doc = JsonDocument.Parse(output);
                    var root = doc.RootElement;

                    if (root.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in root.EnumerateArray())
                            apps.Add(ToDict(el, timestamp));
                    }
                    else if (root.ValueKind == JsonValueKind.Object)
                    {
                        apps.Add(ToDict(root, timestamp));
                    }
                }
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "store_apps.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(apps, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = apps.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static Dictionary<string, object?> ToDict(JsonElement el, string timestamp)
    {
        var d = new Dictionary<string, object?>();
        foreach (var p in el.EnumerateObject())
            d[p.Name.ToLowerInvariant()] = p.Value.ValueKind == JsonValueKind.String
                ? p.Value.GetString()
                : p.Value.ToString();
        d["collection_timestamp"] = timestamp;
        return d;
    }
}
