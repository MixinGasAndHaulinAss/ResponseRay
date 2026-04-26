using System.Diagnostics;
using System.Text.Json;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Scans Downloads, Desktop, and AppData\Local\Temp for files with a Zone.Identifier alternate
/// data stream and emits structured JSON identifying the source zone, referrer, and host URL.
/// This is the standard "Mark of the Web" signal — extremely useful for ID'ing how an attacker
/// payload landed on the box.
/// </summary>
public class ZoneIdentifierCollector : ICollector
{
    public string Name => "ZoneIdentifier";
    public string Description => "Zone.Identifier (Mark of the Web) ADS for downloaded files";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var entries = new List<Dictionary<string, object?>>();

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            string[] roots =
            [
                Path.Combine(userDir, "Downloads"),
                Path.Combine(userDir, "Desktop"),
                Path.Combine(userDir, "Documents"),
                Path.Combine(userDir, "AppData", "Local", "Temp"),
            ];

            foreach (var root in roots)
            {
                if (!Directory.Exists(root)) continue;
                EnumerateZoneIds(root, username, timestamp, entries);
            }
        }

        var dest = Path.Combine(destDir, "zone_identifiers.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = entries.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void EnumerateZoneIds(string root, string username, string timestamp,
        List<Dictionary<string, object?>> entries)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                var ads = file + ":Zone.Identifier";
                try
                {
                    using var stream = new FileStream(ads, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using var reader = new StreamReader(stream);
                    var content = reader.ReadToEnd();

                    var dict = new Dictionary<string, object?>
                    {
                        ["file"] = file,
                        ["user"] = username,
                        ["raw"] = content,
                        ["collection_timestamp"] = timestamp
                    };
                    foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var idx = line.IndexOf('=');
                        if (idx <= 0) continue;
                        var k = line.Substring(0, idx).Trim().ToLowerInvariant();
                        var v = line.Substring(idx + 1).Trim();
                        dict[k] = v;
                    }
                    entries.Add(dict);
                }
                catch { /* no ADS */ }
            }
        }
        catch { }
    }
}
