using System.Diagnostics;
using System.Management;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class ServiceCollector : ICollector
{
    public string Name => "Services";
    public string Description => "Windows services";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var services = new List<ServiceInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, StartMode, State, StartName, Description FROM Win32_Service");

            foreach (var obj in searcher.Get())
            {
                services.Add(new ServiceInfo
                {
                    Name = obj["Name"]?.ToString() ?? "",
                    DisplayName = obj["DisplayName"]?.ToString() ?? "",
                    BinaryPath = obj["PathName"]?.ToString() ?? "",
                    StartType = obj["StartMode"]?.ToString() ?? "",
                    Status = obj["State"]?.ToString() ?? "",
                    Account = obj["StartName"]?.ToString() ?? "",
                    Description = obj["Description"]?.ToString() ?? "",
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"Services: {ex.Message}");
        }

        var dest = Path.Combine(destDir, "services.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(services, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = services.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
