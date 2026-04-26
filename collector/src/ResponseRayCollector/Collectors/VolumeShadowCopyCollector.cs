using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ResponseRayCollector.Collectors;

public class VolumeShadowCopyCollector : ICollector
{
    public string Name => "VolumeShadowCopies";
    public string Description => "Enumeration of existing Volume Shadow Copies (vssadmin list shadows)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var shadows = new List<Dictionary<string, object?>>();

        try
        {
            var psi = new ProcessStartInfo("vssadmin", "list shadows")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(30_000);

                var setRegex = new Regex(@"Contents of shadow copy set ID:\s*(\{[^}]+\})", RegexOptions.IgnoreCase);
                var blockRegex = new Regex(
                    @"Shadow Copy ID:\s*(?<id>\{[^}]+\}).*?" +
                    @"Original Volume:\s*\((?<orig>[^)]+)\)\s*(?<orig_path>[^\r\n]+).*?" +
                    @"Shadow Copy Volume:\s*(?<shadow_path>[^\r\n]+).*?" +
                    @"Originating Machine:\s*(?<host>[^\r\n]+).*?" +
                    @"Service Machine:\s*(?<service>[^\r\n]+).*?" +
                    @"Provider:\s*(?<provider>[^\r\n]+).*?" +
                    @"Type:\s*(?<type>[^\r\n]+).*?" +
                    @"Attributes:\s*(?<attr>[^\r\n]+)",
                    RegexOptions.Singleline | RegexOptions.IgnoreCase);

                foreach (Match m in blockRegex.Matches(output))
                {
                    shadows.Add(new Dictionary<string, object?>
                    {
                        ["shadow_id"] = m.Groups["id"].Value.Trim(),
                        ["original_volume_letter"] = m.Groups["orig"].Value.Trim(),
                        ["original_volume_path"] = m.Groups["orig_path"].Value.Trim(),
                        ["shadow_path"] = m.Groups["shadow_path"].Value.Trim(),
                        ["originating_machine"] = m.Groups["host"].Value.Trim(),
                        ["service_machine"] = m.Groups["service"].Value.Trim(),
                        ["provider"] = m.Groups["provider"].Value.Trim(),
                        ["type"] = m.Groups["type"].Value.Trim(),
                        ["attributes"] = m.Groups["attr"].Value.Trim(),
                        ["collection_timestamp"] = timestamp
                    });
                }
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "volume_shadow_copies.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(shadows, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = shadows.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }
}
