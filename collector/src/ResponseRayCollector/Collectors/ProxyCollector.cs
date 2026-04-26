using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace ResponseRayCollector.Collectors;

public class ProxyCollector : ICollector
{
    public string Name => "Proxy";
    public string Description => "WinINET proxy settings (per user) and WinHTTP proxy";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var output = new Dictionary<string, object?>
        {
            ["collection_timestamp"] = timestamp,
            ["winhttp"] = ReadWinHttp(),
            ["users"] = new List<Dictionary<string, object?>>(),
        };
        var users = (List<Dictionary<string, object?>>)output["users"]!;

        try
        {
            using var hku = Registry.Users;
            foreach (var sid in hku.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-")) continue;
                using var k = hku.OpenSubKey($@"{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (k == null) continue;

                users.Add(new Dictionary<string, object?>
                {
                    ["sid"] = sid,
                    ["proxy_enable"] = k.GetValue("ProxyEnable"),
                    ["proxy_server"] = k.GetValue("ProxyServer")?.ToString(),
                    ["proxy_override"] = k.GetValue("ProxyOverride")?.ToString(),
                    ["auto_config_url"] = k.GetValue("AutoConfigURL")?.ToString(),
                    ["auto_detect"] = k.GetValue("AutoDetect"),
                });
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "proxy.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = 1,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static Dictionary<string, object?> ReadWinHttp()
    {
        var dict = new Dictionary<string, object?>();
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
            var bytes = k?.GetValue("WinHttpSettings") as byte[];
            if (bytes != null)
                dict["winhttp_settings_hex"] = Convert.ToHexString(bytes);
        }
        catch { }
        return dict;
    }
}
