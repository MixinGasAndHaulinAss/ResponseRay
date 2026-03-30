using System.Diagnostics;
using System.Management;
using System.Text.Json;
using Microsoft.Win32;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class DeviceCollector : ICollector
{
    public string Name => "Devices";
    public string Description => "Attached devices (USB, PnP)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var devices = new List<DeviceInfo>();

        // PnP devices via WMI
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DeviceID, Manufacturer, Status, PNPClass FROM Win32_PnPEntity");

            foreach (var obj in searcher.Get())
            {
                devices.Add(new DeviceInfo
                {
                    Name = obj["Name"]?.ToString() ?? "",
                    DeviceId = obj["DeviceID"]?.ToString() ?? "",
                    Manufacturer = obj["Manufacturer"]?.ToString() ?? "",
                    Status = obj["Status"]?.ToString() ?? "",
                    ClassName = obj["PNPClass"]?.ToString() ?? "",
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"PnP devices: {ex.Message}");
        }

        // USB storage device history from registry
        try
        {
            using var usbstorKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (usbstorKey != null)
            {
                foreach (var deviceClass in usbstorKey.GetSubKeyNames())
                {
                    using var classKey = usbstorKey.OpenSubKey(deviceClass);
                    if (classKey == null) continue;

                    foreach (var serial in classKey.GetSubKeyNames())
                    {
                        using var serialKey = classKey.OpenSubKey(serial);
                        var friendlyName = serialKey?.GetValue("FriendlyName")?.ToString() ?? deviceClass;

                        // Only add if not already in the PnP list
                        var deviceId = $@"USBSTOR\{deviceClass}\{serial}";
                        if (!devices.Any(d => d.DeviceId.Contains(serial, StringComparison.OrdinalIgnoreCase)))
                        {
                            devices.Add(new DeviceInfo
                            {
                                Name = friendlyName,
                                DeviceId = deviceId,
                                Manufacturer = "",
                                Status = "Historical",
                                ClassName = "USBSTOR",
                                SerialNumber = serial,
                                CollectionTimestamp = timestamp
                            });
                        }
                    }
                }
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "devices.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = devices.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
