using System.Diagnostics;
using System.Management;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Inventories registered antivirus, antispyware, and firewall providers from
/// SecurityCenter2 (the same data Windows Security uses to display 3rd-party AV).
/// </summary>
public class AntivirusCollector : ICollector
{
    public string Name => "Antivirus";
    public string Description => "Registered AV / antispyware / firewall providers (SecurityCenter2)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var providers = new List<Dictionary<string, object?>>();

        foreach (var (cls, kind) in new[]
                 {
                     ("AntiVirusProduct", "antivirus"),
                     ("AntiSpywareProduct", "antispyware"),
                     ("FirewallProduct", "firewall"),
                 })
        {
            try
            {
                using var s = new ManagementObjectSearcher(@"root\SecurityCenter2", $"SELECT * FROM {cls}");
                foreach (var p in s.Get())
                {
                    providers.Add(new Dictionary<string, object?>
                    {
                        ["kind"] = kind,
                        ["display_name"] = p["displayName"]?.ToString(),
                        ["instance_guid"] = p["instanceGuid"]?.ToString(),
                        ["product_state"] = p["productState"]?.ToString(),
                        ["path_to_signed_product_exe"] = p["pathToSignedProductExe"]?.ToString(),
                        ["timestamp"] = p["timestamp"]?.ToString(),
                        ["collection_timestamp"] = timestamp
                    });
                }
            }
            catch { }
        }

        var dest = Path.Combine(destDir, "antivirus.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(providers, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = providers.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
