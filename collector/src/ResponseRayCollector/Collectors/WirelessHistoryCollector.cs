using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace ResponseRayCollector.Collectors;

public class WirelessHistoryCollector : ICollector
{
    public string Name => "WirelessHistory";
    public string Description => "Wireless network profiles (NetworkList) and known networks";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var profiles = new List<Dictionary<string, object?>>();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles");
            if (key != null)
            {
                foreach (var profileGuid in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(profileGuid);
                    if (sub == null) continue;
                    profiles.Add(new Dictionary<string, object?>
                    {
                        ["profile_guid"] = profileGuid,
                        ["profile_name"] = sub.GetValue("ProfileName")?.ToString(),
                        ["description"] = sub.GetValue("Description")?.ToString(),
                        ["category"] = sub.GetValue("Category"),
                        ["managed"] = sub.GetValue("Managed"),
                        ["name_type"] = sub.GetValue("NameType"),
                        ["date_created"] = ParseSystemTime(sub.GetValue("DateCreated") as byte[]),
                        ["date_last_connected"] = ParseSystemTime(sub.GetValue("DateLastConnected") as byte[]),
                        ["collection_timestamp"] = timestamp
                    });
                }
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "wireless_profiles.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(profiles, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = profiles.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static string? ParseSystemTime(byte[]? bytes)
    {
        if (bytes == null || bytes.Length < 16) return null;
        try
        {
            short year = BitConverter.ToInt16(bytes, 0);
            short month = BitConverter.ToInt16(bytes, 2);
            short day = BitConverter.ToInt16(bytes, 6);
            short hour = BitConverter.ToInt16(bytes, 8);
            short minute = BitConverter.ToInt16(bytes, 10);
            short second = BitConverter.ToInt16(bytes, 12);
            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Local)
                .ToUniversalTime().ToString("o");
        }
        catch { return null; }
    }
}
