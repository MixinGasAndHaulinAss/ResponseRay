using System.Diagnostics;
using System.Management;
using System.Text.Json;

namespace ResponseRayCollector.Collectors;

public class DriverCollector : ICollector
{
    public string Name => "Drivers";
    public string Description => "Loaded kernel drivers via Win32_SystemDriver and Win32_PnPSignedDriver";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var drivers = new List<Dictionary<string, object?>>();

        try
        {
            using var sysSearcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, Description, PathName, ServiceType, StartMode, State, Status, StartName, AcceptPause, AcceptStop FROM Win32_SystemDriver");
            foreach (var d in sysSearcher.Get())
            {
                drivers.Add(new Dictionary<string, object?>
                {
                    ["source"] = "Win32_SystemDriver",
                    ["name"] = d["Name"]?.ToString(),
                    ["display_name"] = d["DisplayName"]?.ToString(),
                    ["description"] = d["Description"]?.ToString(),
                    ["path"] = d["PathName"]?.ToString(),
                    ["service_type"] = d["ServiceType"]?.ToString(),
                    ["start_mode"] = d["StartMode"]?.ToString(),
                    ["state"] = d["State"]?.ToString(),
                    ["status"] = d["Status"]?.ToString(),
                    ["start_name"] = d["StartName"]?.ToString(),
                    ["collection_timestamp"] = timestamp
                });
            }
        }
        catch { }

        try
        {
            using var pnp = new ManagementObjectSearcher(
                "SELECT DeviceName, DriverName, DriverVersion, DriverDate, InfName, IsSigned, Manufacturer, Signer FROM Win32_PnPSignedDriver");
            foreach (var d in pnp.Get())
            {
                drivers.Add(new Dictionary<string, object?>
                {
                    ["source"] = "Win32_PnPSignedDriver",
                    ["device_name"] = d["DeviceName"]?.ToString(),
                    ["driver_name"] = d["DriverName"]?.ToString(),
                    ["driver_version"] = d["DriverVersion"]?.ToString(),
                    ["driver_date"] = d["DriverDate"]?.ToString(),
                    ["inf_name"] = d["InfName"]?.ToString(),
                    ["is_signed"] = d["IsSigned"],
                    ["manufacturer"] = d["Manufacturer"]?.ToString(),
                    ["signer"] = d["Signer"]?.ToString(),
                    ["collection_timestamp"] = timestamp
                });
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "drivers.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(drivers, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = drivers.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
