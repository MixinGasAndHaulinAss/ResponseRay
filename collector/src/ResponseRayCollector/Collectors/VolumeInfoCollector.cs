using System.Diagnostics;
using System.Management;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class VolumeInfoCollector : ICollector
{
    public string Name => "Volumes";
    public string Description => "Logical volumes, disk drives, partitions, BitLocker status";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var output = new Dictionary<string, object?>
        {
            ["collection_timestamp"] = timestamp,
            ["logical_disks"] = QueryAll("SELECT * FROM Win32_LogicalDisk", null),
            ["disk_drives"] = QueryAll("SELECT * FROM Win32_DiskDrive", null),
            ["partitions"] = QueryAll("SELECT * FROM Win32_DiskPartition", null),
            ["volumes"] = QueryAll("SELECT * FROM Win32_Volume", null),
            ["bitlocker"] = QueryAll("SELECT * FROM Win32_EncryptableVolume", @"root\cimv2\Security\MicrosoftVolumeEncryption"),
        };

        var dest = Path.Combine(destDir, "volumes.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = ((List<Dictionary<string, object?>>)output["logical_disks"]!).Count
                           + ((List<Dictionary<string, object?>>)output["disk_drives"]!).Count
                           + ((List<Dictionary<string, object?>>)output["partitions"]!).Count
                           + ((List<Dictionary<string, object?>>)output["volumes"]!).Count
                           + ((List<Dictionary<string, object?>>)output["bitlocker"]!).Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static List<Dictionary<string, object?>> QueryAll(string query, string? scope)
    {
        var list = new List<Dictionary<string, object?>>();
        try
        {
            using var s = scope != null
                ? new ManagementObjectSearcher(scope, query)
                : new ManagementObjectSearcher(query);
            foreach (var obj in s.Get())
            {
                var dict = new Dictionary<string, object?>();
                foreach (var prop in obj.Properties)
                {
                    try { dict[prop.Name] = prop.Value?.ToString(); }
                    catch { }
                }
                list.Add(dict);
            }
        }
        catch { }
        return list;
    }
}
