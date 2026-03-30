using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class RegistryCollector : ICollector
{
    public string Name => "Registry";
    public string Description => "Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve)";

    private static readonly string[] SystemHives = ["SAM", "SYSTEM", "SOFTWARE", "SECURITY"];

    private static readonly Dictionary<string, string> RegSaveKeys = new()
    {
        ["SAM"] = @"HKLM\SAM",
        ["SYSTEM"] = @"HKLM\SYSTEM",
        ["SOFTWARE"] = @"HKLM\SOFTWARE",
        ["SECURITY"] = @"HKLM\SECURITY"
    };

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "registry");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var configDir = Path.Combine(winDir, "System32", "config");

        foreach (var hive in SystemHives)
        {
            var dest = Path.Combine(destDir, hive);
            var originalPath = $@"C:\Windows\System32\config\{hive}";

            // Try VSS first, then direct copy, then reg save fallback
            var src = GetSource(context, Path.Combine(configDir, hive));
            if (TryCopy(src, dest, context, originalPath, "registry", out var size))
            {
                count++;
                bytes += size;
            }
            else if (TryRegSave(hive, dest, context, originalPath, out size))
            {
                count++;
                bytes += size;
                ConsoleOutput.Status($"  {hive}: captured via reg save fallback");
            }
        }

        // Amcache
        var amcachePath = Path.Combine(winDir, "AppCompat", "Programs", "Amcache.hve");
        var amcacheDest = Path.Combine(destDir, "Amcache.hve");
        var amcacheSrc = GetSource(context, amcachePath);
        if (TryCopy(amcacheSrc, amcacheDest, context, amcachePath, "registry", out var amcacheSize))
        {
            count++;
            bytes += amcacheSize;
        }
        else if (TryEsentutlCopy(amcachePath, amcacheDest, context, "registry", out amcacheSize))
        {
            count++;
            bytes += amcacheSize;
            ConsoleOutput.Status($"  Amcache.hve: captured via esentutl fallback");
        }

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir);

            // NTUSER.DAT -- try VSS/direct, then reg save, then esentutl
            var ntuserPath = Path.Combine(userDir, "NTUSER.DAT");
            var ntuserDest = Path.Combine(destDir, $"{username}_NTUSER.DAT");
            var ntuserSrc = GetSource(context, ntuserPath);
            if (TryCopy(ntuserSrc, ntuserDest, context, ntuserPath, "registry", out var ntuserSize))
            {
                count++;
                bytes += ntuserSize;
            }
            else if (TryRegSaveUser(username, ntuserDest, context, ntuserPath, out ntuserSize))
            {
                count++;
                bytes += ntuserSize;
                ConsoleOutput.Status($"  {username} NTUSER.DAT: captured via reg save fallback");
            }
            else if (TryEsentutlCopy(ntuserPath, ntuserDest, context, "registry", out ntuserSize))
            {
                count++;
                bytes += ntuserSize;
                ConsoleOutput.Status($"  {username} NTUSER.DAT: captured via esentutl fallback");
            }

            // UsrClass.dat -- try VSS/direct, then esentutl
            var usrClassPath = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat");
            var usrClassDest = Path.Combine(destDir, $"{username}_UsrClass.dat");
            var usrClassSrc = GetSource(context, usrClassPath);
            if (TryCopy(usrClassSrc, usrClassDest, context, usrClassPath, "registry", out var usrClassSize))
            {
                count++;
                bytes += usrClassSize;
            }
            else if (TryEsentutlCopy(usrClassPath, usrClassDest, context, "registry", out usrClassSize))
            {
                count++;
                bytes += usrClassSize;
                ConsoleOutput.Status($"  {username} UsrClass.dat: captured via esentutl fallback");
            }
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = bytes,
            Elapsed = sw.Elapsed
        };
    }

    private static bool TryRegSave(string hiveName, string dest, CollectionContext context, string originalPath, out long size)
    {
        size = 0;
        if (!RegSaveKeys.TryGetValue(hiveName, out var regKey))
            return false;

        try
        {
            var tempPath = Path.Combine(Path.GetTempPath(), $"rr_{hiveName}_{Guid.NewGuid():N}.tmp");
            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "reg",
                Arguments = $"save \"{regKey}\" \"{tempPath}\" /y",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            proc?.WaitForExit(30_000);

            if (proc?.ExitCode == 0 && File.Exists(tempPath))
            {
                FileHelper.SafeCopy(tempPath, dest);
                File.Delete(tempPath);
                size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = originalPath,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "registry",
                    Size = size
                });
                return true;
            }

            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
        catch { }
        return false;
    }

    private static bool TryRegSaveUser(string username, string dest, CollectionContext context, string originalPath, out long size)
    {
        size = 0;
        try
        {
            // Find the user's SID to use HKU\<SID>
            var sid = GetUserSid(username);
            if (string.IsNullOrEmpty(sid)) return false;

            var tempPath = Path.Combine(Path.GetTempPath(), $"rr_ntuser_{Guid.NewGuid():N}.tmp");
            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "reg",
                Arguments = $"save \"HKU\\{sid}\" \"{tempPath}\" /y",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            proc?.WaitForExit(30_000);

            if (proc?.ExitCode == 0 && File.Exists(tempPath))
            {
                FileHelper.SafeCopy(tempPath, dest);
                File.Delete(tempPath);
                size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = originalPath,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "registry",
                    Size = size
                });
                return true;
            }

            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
        catch { }
        return false;
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

    private static string GetSource(CollectionContext context, string originalPath)
    {
        if (!string.IsNullOrEmpty(context.VssRoot))
        {
            var vssPath = FileHelper.ResolveVssPath(context.VssRoot, originalPath);
            if (File.Exists(vssPath))
                return vssPath;
        }
        return originalPath;
    }

    private static bool TryCopy(string source, string dest, CollectionContext context, string originalPath, string category, out long size)
    {
        size = 0;
        try
        {
            if (!File.Exists(source)) return false;
            FileHelper.SafeCopy(source, dest);
            size = new FileInfo(dest).Length;
            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = originalPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                Category = category,
                Size = size
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryEsentutlCopy(string source, string dest, CollectionContext context, string category, out long size)
    {
        size = 0;
        try
        {
            if (!File.Exists(source)) return false;
            var dir = Path.GetDirectoryName(dest);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "esentutl.exe",
                Arguments = $"/y \"{source}\" /d \"{dest}\" /o",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            proc?.WaitForExit(60_000);

            if (proc?.ExitCode == 0 && File.Exists(dest) && new FileInfo(dest).Length > 0)
            {
                size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = source,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = category,
                    Size = size
                });
                return true;
            }

            try { if (File.Exists(dest)) File.Delete(dest); } catch { }
        }
        catch { }
        return false;
    }
}
