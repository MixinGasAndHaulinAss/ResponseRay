using System.Security.Cryptography;

namespace ResponseRayCollector.Utils;

public static class FileHelper
{
    public static void SafeCopy(string source, string destination)
    {
        var dir = Path.GetDirectoryName(destination);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        try
        {
            File.Copy(source, destination, overwrite: true);
        }
        catch (IOException)
        {
            // File is locked (e.g. browser History DB) -- read with shared access
            using var src = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var dst = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
            src.CopyTo(dst);
        }
    }

    public static int CopyDirectory(string sourceDir, string destDir, string searchPattern = "*", SearchOption option = SearchOption.TopDirectoryOnly)
    {
        if (!Directory.Exists(sourceDir))
            return 0;

        int count = 0;
        foreach (var file in Directory.EnumerateFiles(sourceDir, searchPattern, option))
        {
            try
            {
                var relativePath = Path.GetRelativePath(sourceDir, file);
                var dest = Path.Combine(destDir, relativePath);
                SafeCopy(file, dest);
                count++;
            }
            catch (Exception ex)
            {
                ConsoleOutput.Warning($"Could not copy {file}: {ex.Message}");
            }
        }
        return count;
    }

    public static string ComputeMd5(string filePath)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            var hash = MD5.HashData(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        catch
        {
            return "";
        }
    }

    public static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }

    public static long GetDirectorySize(string path)
    {
        if (!Directory.Exists(path)) return 0;
        return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
            .Sum(f =>
            {
                try { return new FileInfo(f).Length; }
                catch { return 0L; }
            });
    }

    public static IEnumerable<string> GetUserProfilePaths()
    {
        var usersDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86).Substring(0, 3), "Users");
        if (!Directory.Exists(usersDir))
            yield break;

        foreach (var dir in Directory.EnumerateDirectories(usersDir))
        {
            var name = Path.GetFileName(dir).ToLowerInvariant();
            if (name is "public" or "default" or "default user" or "all users")
                continue;
            yield return dir;
        }
    }

    public static string ResolveVssPath(string vssRoot, string originalPath)
    {
        var driveLetter = Path.GetPathRoot(originalPath);
        if (string.IsNullOrEmpty(driveLetter))
            return originalPath;

        var relativePath = originalPath.Substring(driveLetter.Length);
        return Path.Combine(vssRoot, relativePath);
    }
}
