using System.Diagnostics;
using System.Management;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class NetworkAdapterCollector : ICollector
{
    public string Name => "NetworkAdapters";
    public string Description => "Network adapters with MAC, IP, gateway, DHCP, DNS, WINS configuration";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var adapters = new List<Dictionary<string, object?>>();

        try
        {
            using var s = new ManagementObjectSearcher(
                "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");
            foreach (var a in s.Get())
            {
                adapters.Add(new Dictionary<string, object?>
                {
                    ["index"] = a["Index"],
                    ["description"] = a["Description"]?.ToString(),
                    ["mac_address"] = a["MACAddress"]?.ToString(),
                    ["ip_addresses"] = (a["IPAddress"] as string[]) ?? Array.Empty<string>(),
                    ["ip_subnets"] = (a["IPSubnet"] as string[]) ?? Array.Empty<string>(),
                    ["default_gateways"] = (a["DefaultIPGateway"] as string[]) ?? Array.Empty<string>(),
                    ["dns_servers"] = (a["DNSServerSearchOrder"] as string[]) ?? Array.Empty<string>(),
                    ["dns_domain"] = a["DNSDomain"]?.ToString(),
                    ["dhcp_enabled"] = a["DHCPEnabled"],
                    ["dhcp_server"] = a["DHCPServer"]?.ToString(),
                    ["dhcp_lease_obtained"] = a["DHCPLeaseObtained"]?.ToString(),
                    ["dhcp_lease_expires"] = a["DHCPLeaseExpires"]?.ToString(),
                    ["wins_primary"] = a["WINSPrimaryServer"]?.ToString(),
                    ["wins_secondary"] = a["WINSSecondaryServer"]?.ToString(),
                    ["domain_dns_registration"] = a["DomainDNSRegistrationEnabled"],
                    ["full_dns_registration"] = a["FullDNSRegistrationEnabled"],
                    ["collection_timestamp"] = timestamp
                });
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "network_adapters.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(adapters, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = adapters.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
