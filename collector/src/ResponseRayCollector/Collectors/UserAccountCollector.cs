using System.Diagnostics;
using System.Management;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class UserAccountCollector : ICollector
{
    public string Name => "UserAccounts";
    public string Description => "Local user accounts";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var accounts = new List<UserAccountInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_UserAccount WHERE LocalAccount=TRUE");

            foreach (var obj in searcher.Get())
            {
                var username = obj["Name"]?.ToString() ?? "";
                accounts.Add(new UserAccountInfo
                {
                    Username = username,
                    FullName = obj["FullName"]?.ToString() ?? "",
                    Sid = obj["SID"]?.ToString() ?? "",
                    IsDisabled = Convert.ToBoolean(obj["Disabled"] ?? false),
                    IsLocked = Convert.ToBoolean(obj["Lockout"] ?? false),
                    Groups = GetUserGroups(username),
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"User accounts: {ex.Message}");
        }

        var dest = Path.Combine(destDir, "user_accounts.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = accounts.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static List<string> GetUserGroups(string username)
    {
        var groups = new List<string>();
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "net",
                Arguments = $"user \"{username}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);

            bool inGroups = false;
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("Local Group Memberships", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("Global Group memberships", StringComparison.OrdinalIgnoreCase))
                {
                    inGroups = true;
                    var parts = trimmed.Split('*', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var part in parts.Skip(1))
                    {
                        var g = part.Trim();
                        if (!string.IsNullOrEmpty(g)) groups.Add(g);
                    }
                }
                else if (inGroups && trimmed.StartsWith("*"))
                {
                    foreach (var part in trimmed.Split('*', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var g = part.Trim();
                        if (!string.IsNullOrEmpty(g)) groups.Add(g);
                    }
                }
                else if (inGroups && !string.IsNullOrEmpty(trimmed) && !trimmed.Contains("*"))
                {
                    inGroups = false;
                }
            }
        }
        catch { }
        return groups;
    }
}
