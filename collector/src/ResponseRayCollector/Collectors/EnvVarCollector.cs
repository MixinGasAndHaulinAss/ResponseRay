using System.Collections;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace ResponseRayCollector.Collectors;

public class EnvVarCollector : ICollector
{
    public string Name => "EnvironmentVariables";
    public string Description => "System and per-user environment variables";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var output = new Dictionary<string, object?>
        {
            ["collection_timestamp"] = timestamp,
            ["machine"] = ConvertEnv(Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Machine)),
            ["process"] = ConvertEnv(Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Process)),
            ["users"] = new List<Dictionary<string, object?>>()
        };
        var users = (List<Dictionary<string, object?>>)output["users"]!;

        try
        {
            using var hku = Registry.Users;
            foreach (var sid in hku.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-")) continue;
                using var env = hku.OpenSubKey($@"{sid}\Environment");
                if (env == null) continue;

                var dict = new Dictionary<string, object?> { ["sid"] = sid };
                foreach (var name in env.GetValueNames())
                    dict[name] = env.GetValue(name)?.ToString();

                using var volatileKey = hku.OpenSubKey($@"{sid}\Volatile Environment");
                if (volatileKey != null)
                {
                    foreach (var name in volatileKey.GetValueNames())
                        dict[$"volatile.{name}"] = volatileKey.GetValue(name)?.ToString();
                }
                users.Add(dict);
            }
        }
        catch { }

        var dest = Path.Combine(destDir, "environment_variables.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = 1,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static Dictionary<string, string> ConvertEnv(IDictionary src)
    {
        var d = new Dictionary<string, string>();
        foreach (DictionaryEntry e in src)
        {
            d[e.Key.ToString() ?? ""] = e.Value?.ToString() ?? "";
        }
        return d;
    }
}
