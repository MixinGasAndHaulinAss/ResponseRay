using System.Diagnostics;
using System.Management;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class LogonSessionCollector : ICollector
{
    public string Name => "LogonSessions";
    public string Description => "Active logon sessions";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var sessions = new List<LogonSessionInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_LogonSession");
            var logonMap = GetLogonUserMap();

            foreach (var obj in searcher.Get())
            {
                var logonId = obj["LogonId"]?.ToString() ?? "";
                var logonTypeNum = Convert.ToInt32(obj["LogonType"] ?? 0);

                logonMap.TryGetValue(logonId, out var userInfo);

                sessions.Add(new LogonSessionInfo
                {
                    LogonId = logonId,
                    Username = userInfo?.Username ?? "",
                    Domain = userInfo?.Domain ?? "",
                    Sid = userInfo?.Sid ?? "",
                    LogonType = LogonTypeToString(logonTypeNum),
                    LogonTime = ParseWmiDate(obj["StartTime"]?.ToString()),
                    AuthPackage = obj["AuthenticationPackage"]?.ToString() ?? "",
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"Logon sessions: {ex.Message}");
        }

        var dest = Path.Combine(destDir, "logon_sessions.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(sessions, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = sessions.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static Dictionary<string, LogonUser> GetLogonUserMap()
    {
        var map = new Dictionary<string, LogonUser>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "ASSOCIATORS OF {Win32_LogonSession} WHERE AssocClass=Win32_LoggedOnUser ResultClass=Win32_Account");

            // Fall back to simpler query that maps sessions to users
            using var sessionSearcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_LoggedOnUser");
            foreach (var obj in sessionSearcher.Get())
            {
                var dependent = obj["Dependent"]?.ToString() ?? "";
                var antecedent = obj["Antecedent"]?.ToString() ?? "";

                var logonIdMatch = System.Text.RegularExpressions.Regex.Match(dependent, @"LogonId=""(\d+)""");
                var domainMatch = System.Text.RegularExpressions.Regex.Match(antecedent, @"Domain=""([^""]+)""");
                var nameMatch = System.Text.RegularExpressions.Regex.Match(antecedent, @"Name=""([^""]+)""");

                if (logonIdMatch.Success)
                {
                    map[logonIdMatch.Groups[1].Value] = new LogonUser
                    {
                        Domain = domainMatch.Success ? domainMatch.Groups[1].Value : "",
                        Username = nameMatch.Success ? nameMatch.Groups[1].Value : ""
                    };
                }
            }
        }
        catch { }
        return map;
    }

    private static string? ParseWmiDate(string? wmiDate)
    {
        if (string.IsNullOrEmpty(wmiDate)) return null;
        try
        {
            var dt = ManagementDateTimeConverter.ToDateTime(wmiDate);
            return dt.ToUniversalTime().ToString("o");
        }
        catch { return wmiDate; }
    }

    private static string LogonTypeToString(int type) => type switch
    {
        0 => "System",
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        _ => $"Type{type}"
    };

    private class LogonUser
    {
        public string Username = "";
        public string Domain = "";
        public string Sid = "";
    }
}
