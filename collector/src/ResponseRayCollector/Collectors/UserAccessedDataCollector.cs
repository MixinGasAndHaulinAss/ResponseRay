using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class UserAccessedDataCollector : ICollector
{
    public string Name => "UserAccessedData";
    public string Description => "Jump lists, recent docs, MRU lists, shellbags indicators";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var items = new List<UserAccessedItem>();

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;

            // Jump lists (AutomaticDestinations)
            CollectJumpLists(userDir, username, items, timestamp);

            // Recent folder (beyond just .lnk -- all recent items)
            CollectRecentItems(userDir, username, items, timestamp);

            // Office MRU from registry
            CollectOfficeMru(username, items, timestamp);

            // Explorer typed paths / RunMRU
            CollectTypedPaths(username, items, timestamp);

            // UserAssist (executed programs from Explorer)
            CollectUserAssist(username, items, timestamp);
        }

        var dest = Path.Combine(destDir, "user_accessed_data.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(items, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = items.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void CollectJumpLists(string userDir, string username, List<UserAccessedItem> items, string timestamp)
    {
        var autoDir = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Recent",
            "AutomaticDestinations");
        if (!Directory.Exists(autoDir)) return;

        foreach (var file in Directory.EnumerateFiles(autoDir, "*.automaticDestinations-ms"))
        {
            try
            {
                var fi = new FileInfo(file);
                items.Add(new UserAccessedItem
                {
                    Type = "JumpList",
                    Name = fi.Name,
                    Path = file,
                    User = username,
                    Modified = fi.LastWriteTimeUtc.ToString("o"),
                    Size = fi.Length,
                    CollectionTimestamp = timestamp
                });
            }
            catch { }
        }

        var customDir = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Recent",
            "CustomDestinations");
        if (!Directory.Exists(customDir)) return;

        foreach (var file in Directory.EnumerateFiles(customDir, "*.customDestinations-ms"))
        {
            try
            {
                var fi = new FileInfo(file);
                items.Add(new UserAccessedItem
                {
                    Type = "JumpListCustom",
                    Name = fi.Name,
                    Path = file,
                    User = username,
                    Modified = fi.LastWriteTimeUtc.ToString("o"),
                    Size = fi.Length,
                    CollectionTimestamp = timestamp
                });
            }
            catch { }
        }
    }

    private static void CollectRecentItems(string userDir, string username, List<UserAccessedItem> items, string timestamp)
    {
        var recentDir = Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;

        foreach (var file in Directory.EnumerateFiles(recentDir))
        {
            try
            {
                var fi = new FileInfo(file);
                items.Add(new UserAccessedItem
                {
                    Type = "RecentDoc",
                    Name = fi.Name,
                    Path = file,
                    User = username,
                    Modified = fi.LastWriteTimeUtc.ToString("o"),
                    Size = fi.Length,
                    CollectionTimestamp = timestamp
                });
            }
            catch { }
        }
    }

    private static void CollectOfficeMru(string username, List<UserAccessedItem> items, string timestamp)
    {
        // Try each Office version's MRU in the user's HKU hive
        var sid = GetUserSid(username);
        if (string.IsNullOrEmpty(sid)) return;

        var officePaths = new[]
        {
            @"Software\Microsoft\Office\16.0\Word\Reading Locations",
            @"Software\Microsoft\Office\16.0\Excel\Recent",
            @"Software\Microsoft\Office\16.0\PowerPoint\Recent",
            @"Software\Microsoft\Office\16.0\Common\Open Find\Microsoft Word\Settings\File Name MRU",
        };

        try
        {
            using var hku = Registry.Users.OpenSubKey(sid);
            if (hku == null) return;

            foreach (var path in officePaths)
            {
                try
                {
                    using var key = hku.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var name in key.GetValueNames())
                    {
                        var value = key.GetValue(name)?.ToString() ?? "";
                        if (string.IsNullOrWhiteSpace(value)) continue;

                        items.Add(new UserAccessedItem
                        {
                            Type = "OfficeMRU",
                            Name = name,
                            Path = value,
                            User = username,
                            Detail = path,
                            CollectionTimestamp = timestamp
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CollectTypedPaths(string username, List<UserAccessedItem> items, string timestamp)
    {
        var sid = GetUserSid(username);
        if (string.IsNullOrEmpty(sid)) return;

        try
        {
            using var hku = Registry.Users.OpenSubKey(sid);
            if (hku == null) return;

            // Explorer TypedPaths
            using var typedPaths = hku.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths");
            if (typedPaths != null)
            {
                foreach (var name in typedPaths.GetValueNames())
                {
                    var value = typedPaths.GetValue(name)?.ToString() ?? "";
                    items.Add(new UserAccessedItem
                    {
                        Type = "TypedPath",
                        Name = name,
                        Path = value,
                        User = username,
                        CollectionTimestamp = timestamp
                    });
                }
            }

            // RunMRU
            using var runMru = hku.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
            if (runMru != null)
            {
                foreach (var name in runMru.GetValueNames())
                {
                    if (name == "MRUList") continue;
                    var value = runMru.GetValue(name)?.ToString() ?? "";
                    items.Add(new UserAccessedItem
                    {
                        Type = "RunMRU",
                        Name = name,
                        Path = value.TrimEnd('\x01'),
                        User = username,
                        CollectionTimestamp = timestamp
                    });
                }
            }
        }
        catch { }
    }

    private static void CollectUserAssist(string username, List<UserAccessedItem> items, string timestamp)
    {
        var sid = GetUserSid(username);
        if (string.IsNullOrEmpty(sid)) return;

        try
        {
            using var hku = Registry.Users.OpenSubKey(sid);
            if (hku == null) return;

            using var ua = hku.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua == null) return;

            foreach (var guid in ua.GetSubKeyNames())
            {
                using var countKey = ua.OpenSubKey($@"{guid}\Count");
                if (countKey == null) continue;

                foreach (var name in countKey.GetValueNames())
                {
                    // UserAssist entries are ROT13 encoded
                    var decoded = Rot13(name);
                    items.Add(new UserAccessedItem
                    {
                        Type = "UserAssist",
                        Name = decoded,
                        Path = decoded,
                        User = username,
                        CollectionTimestamp = timestamp
                    });
                }
            }
        }
        catch { }
    }

    private static string Rot13(string input)
    {
        var chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (c is >= 'A' and <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }

    private static string? GetUserSid(string username)
    {
        try
        {
            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = $"useraccount where name=\"{username}\" get sid /value",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            });
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(10_000);
            var match = System.Text.RegularExpressions.Regex.Match(output, @"SID=(S-[\d-]+)");
            return match.Success ? match.Groups[1].Value : null;
        }
        catch { return null; }
    }

    private class UserAccessedItem
    {
        [JsonPropertyName("type")] public string Type { get; set; } = "";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("path")] public string Path { get; set; } = "";
        [JsonPropertyName("user")] public string User { get; set; } = "";
        [JsonPropertyName("modified")] public string? Modified { get; set; }
        [JsonPropertyName("size")] public long? Size { get; set; }
        [JsonPropertyName("detail")] public string? Detail { get; set; }
        [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
    }
}
