using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class DnsServerCollector : ICollector
{
    public string Name => "DnsServers";
    public string Description => "Configured DNS servers for every active network interface";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var entries = new List<Dictionary<string, object?>>();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;

                var ipprops = nic.GetIPProperties();
                entries.Add(new Dictionary<string, object?>
                {
                    ["interface"] = nic.Name,
                    ["description"] = nic.Description,
                    ["mac"] = string.Join(":", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2"))),
                    ["dns_suffix"] = ipprops.DnsSuffix,
                    ["dns_servers"] = ipprops.DnsAddresses.Select(a => a.ToString()).ToList(),
                    ["wins_servers"] = ipprops.WinsServersAddresses.Select(a => a.ToString()).ToList(),
                    ["gateways"] = ipprops.GatewayAddresses.Select(g => g.Address.ToString()).ToList(),
                    ["collection_timestamp"] = timestamp
                });
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "dns_servers.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = entries.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
