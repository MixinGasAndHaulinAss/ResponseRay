using System.Diagnostics;
using System.Management;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class RestorePointCollector : ICollector
{
    public string Name => "RestorePoints";
    public string Description => "System Restore points (SystemRestore WMI)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var points = new List<Dictionary<string, object?>>();

        try
        {
            using var s = new ManagementObjectSearcher(@"root\default", "SELECT * FROM SystemRestore");
            foreach (var p in s.Get())
            {
                points.Add(new Dictionary<string, object?>
                {
                    ["sequence_number"] = p["SequenceNumber"],
                    ["description"] = p["Description"]?.ToString(),
                    ["creation_time"] = p["CreationTime"]?.ToString(),
                    ["restore_point_type"] = p["RestorePointType"],
                    ["event_type"] = p["EventType"],
                    ["collection_timestamp"] = timestamp
                });
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "restore_points.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(points, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = points.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
