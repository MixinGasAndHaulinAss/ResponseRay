using System.Diagnostics;
using System.Management;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class NetworkShareCollector : ICollector
{
    public string Name => "NetworkShares";
    public string Description => "Local SMB shares (Win32_Share) and active SMB sessions (Win32_ServerConnection)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var output = new Dictionary<string, object?>
        {
            ["collection_timestamp"] = timestamp,
            ["shares"] = new List<Dictionary<string, object?>>(),
            ["server_connections"] = new List<Dictionary<string, object?>>(),
        };
        var shares = (List<Dictionary<string, object?>>)output["shares"]!;
        var conns = (List<Dictionary<string, object?>>)output["server_connections"]!;

        try
        {
            using var s = new ManagementObjectSearcher("SELECT * FROM Win32_Share");
            foreach (var sh in s.Get())
            {
                shares.Add(new Dictionary<string, object?>
                {
                    ["name"] = sh["Name"]?.ToString(),
                    ["path"] = sh["Path"]?.ToString(),
                    ["description"] = sh["Description"]?.ToString(),
                    ["type"] = sh["Type"],
                    ["allow_maximum"] = sh["AllowMaximum"],
                    ["maximum_allowed"] = sh["MaximumAllowed"],
                });
            }
        }
        catch { }

        try
        {
            using var s = new ManagementObjectSearcher("SELECT * FROM Win32_ServerConnection");
            foreach (var c in s.Get())
            {
                conns.Add(new Dictionary<string, object?>
                {
                    ["computer_name"] = c["ComputerName"]?.ToString(),
                    ["user_name"] = c["UserName"]?.ToString(),
                    ["share_name"] = c["ShareName"]?.ToString(),
                    ["active_time"] = c["ActiveTime"],
                    ["connection_id"] = c["ConnectionID"],
                    ["num_users"] = c["NumberOfUsers"],
                });
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "network_shares.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = shares.Count + conns.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
