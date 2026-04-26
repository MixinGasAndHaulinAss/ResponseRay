using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace ResponseRayCollector.Collectors;

public class DefaultBrowserCollector : ICollector
{
    public string Name => "DefaultBrowser";
    public string Description => "Default browser and protocol associations (per user)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var entries = new List<Dictionary<string, object?>>();

        try
        {
            using var hku = Registry.Users;
            foreach (var sid in hku.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-")) continue;

                var entry = new Dictionary<string, object?>
                {
                    ["sid"] = sid,
                    ["collection_timestamp"] = timestamp,
                };

                foreach (var (proto, label) in new[] { ("http", "default_http"), ("https", "default_https"), ("ftp", "default_ftp") })
                {
                    using var k = hku.OpenSubKey($@"{sid}\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\{proto}\UserChoice");
                    entry[label] = k?.GetValue("ProgId")?.ToString();
                }

                foreach (var (ext, label) in new[] { (".html", "default_html"), (".htm", "default_htm"), (".pdf", "default_pdf") })
                {
                    using var k = hku.OpenSubKey($@"{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}\UserChoice");
                    entry[label] = k?.GetValue("ProgId")?.ToString();
                }

                entries.Add(entry);
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "default_browser.json");
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
