using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ResponseRayCollector.Utils;

public static class FileHelper
{
    #region P/Invoke

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr prev, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint FILE_SHARE_DELETE = 0x04;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x02;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    #endregion

    public static void EnablePrivilege(string privilegeName)
    {
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
                return;
            if (!LookupPrivilegeValue(null, privilegeName, out var luid))
            {
                CloseHandle(token);
                return;
            }

            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(token);
        }
        catch { }
    }

    /// <summary>
    /// Checks whether a file exists using CreateFile with FILE_FLAG_BACKUP_SEMANTICS.
    /// Unlike File.Exists, this respects SeBackupPrivilege and can detect files
    /// the caller lacks standard read permissions for (e.g. locked registry hives).
    /// </summary>
    public static bool FileExistsViaBackup(string path)
    {
        var h = CreateFile(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == IntPtr.Zero || h == INVALID_HANDLE_VALUE)
            return false;
        CloseHandle(h);
        return true;
    }

    /// <summary>
    /// Copies a file using CreateFile with FILE_FLAG_BACKUP_SEMANTICS.
    /// When SeBackupPrivilege is enabled this bypasses all file locks and
    /// NTFS security, making it the primary method for locked hives,
    /// browser databases, and other in-use files.
    /// </summary>
    public static void BackupCopy(string source, string dest)
    {
        var dir = Path.GetDirectoryName(dest);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var hFile = CreateFile(source, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);

        if (hFile == IntPtr.Zero || hFile == INVALID_HANDLE_VALUE)
        {
            int err = Marshal.GetLastWin32Error();
            throw new IOException($"CreateFile failed for {source} (Win32={err})");
        }

        try
        {
            using var safeHandle = new SafeFileHandle(hFile, ownsHandle: false);
            using var src = new FileStream(safeHandle, FileAccess.Read, 1024 * 1024, false);
            using var dst = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024);
            src.CopyTo(dst, 1024 * 1024);
        }
        finally
        {
            CloseHandle(hFile);
        }
    }

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
            BackupCopy(source, destination);
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
}
