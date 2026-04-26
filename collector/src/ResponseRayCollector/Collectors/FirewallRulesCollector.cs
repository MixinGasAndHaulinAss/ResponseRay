using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace ResponseRayCollector.Collectors;

public class FirewallRulesCollector : ICollector
{
    public string Name => "FirewallRules";
    public string Description => "Full Windows Firewall rule set (registry-derived)";

    private static readonly string[] RuleKeys =
    [
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System",
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System",
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var rules = new List<Dictionary<string, object?>>();

        foreach (var keyPath in RuleKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key == null) continue;

                foreach (var name in key.GetValueNames())
                {
                    var raw = key.GetValue(name)?.ToString();
                    if (string.IsNullOrEmpty(raw)) continue;
                    var rule = ParseRule(raw);
                    rule["registry_key"] = keyPath;
                    rule["rule_id"] = name;
                    rule["collection_timestamp"] = timestamp;
                    rules.Add(rule);
                }
            }
            catch { }
        }

        var dest = Path.Combine(destDir, "firewall_rules.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(rules, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = rules.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static Dictionary<string, object?> ParseRule(string rule)
    {
        var dict = new Dictionary<string, object?> { ["raw"] = rule };
        foreach (var part in rule.Split('|'))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0) continue;
            var k = part.Substring(0, idx).ToLowerInvariant();
            var v = part.Substring(idx + 1);
            // Don't overwrite the canonical 'raw' key.
            if (k == "raw") k = "raw_field";
            dict[k] = v;
        }
        return dict;
    }
}
