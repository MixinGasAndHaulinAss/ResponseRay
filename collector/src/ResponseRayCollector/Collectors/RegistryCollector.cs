using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class RegistryCollector : ICollector
{
    public string Name => "Registry";
    public string Description => "Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve)";

    private static readonly (string HiveName, string RegKey)[] SystemHives =
    [
        ("SAM", @"HKLM\SAM"),
        ("SYSTEM", @"HKLM\SYSTEM"),
        ("SOFTWARE", @"HKLM\SOFTWARE"),
        ("SECURITY", @"HKLM\SECURITY"),
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "registry");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var (hiveName, regKey) in SystemHives)
        {
            var dest = Path.Combine(destDir, hiveName);
            var originalPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "config", hiveName);

            if (TryCaptureViaRegSave(regKey, dest, originalPath, context, ref count, ref bytes))
            {
                ConsoleOutput.Status($"  {hiveName}: captured (reg save)");
            }
            else if (TryCaptureViaBackup(originalPath, dest, originalPath, context, ref count, ref bytes))
            {
                ConsoleOutput.Status($"  {hiveName}: captured (backup)");
            }
            else
            {
                ConsoleOutput.Warning($"  {hiveName}: all capture methods failed");
            }
        }

        // Amcache
        var amcachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "AppCompat", "Programs", "Amcache.hve");
        var amcacheDest = Path.Combine(destDir, "Amcache.hve");
        if (TryCaptureViaRegSave(@"HKLM\SOFTWARE\Microsoft\Amcache", amcacheDest, amcachePath, context, ref count, ref bytes))
        {
            ConsoleOutput.Status("  Amcache.hve: captured (reg save)");
        }
        else if (TryCaptureViaBackup(amcachePath, amcacheDest, amcachePath, context, ref count, ref bytes))
        {
            ConsoleOutput.Status("  Amcache.hve: captured (backup)");
        }

        // Per-user hives
        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir);

            var ntuserPath = Path.Combine(userDir, "NTUSER.DAT");
            var ntuserDest = Path.Combine(destDir, $"{username}_NTUSER.DAT");
            if (TryCaptureViaBackup(ntuserPath, ntuserDest, ntuserPath, context, ref count, ref bytes))
                ConsoleOutput.Status($"  {username} NTUSER.DAT: captured");
            else
                ConsoleOutput.Warning($"  {username} NTUSER.DAT: capture failed");

            var usrClassPath = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat");
            var usrClassDest = Path.Combine(destDir, $"{username}_UsrClass.dat");
            if (TryCaptureViaBackup(usrClassPath, usrClassDest, usrClassPath, context, ref count, ref bytes))
                ConsoleOutput.Status($"  {username} UsrClass.dat: captured");
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = bytes,
            Elapsed = sw.Elapsed
        };
    }

    private static bool TryCaptureViaRegSave(string regKey, string dest, string originalPath,
        CollectionContext context, ref int count, ref long bytes)
    {
        try
        {
            var psi = new ProcessStartInfo("reg", $"save \"{regKey}\" \"{dest}\" /y")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            proc.WaitForExit(30_000);

            if (proc.ExitCode != 0 || !File.Exists(dest))
                return false;

            var size = new FileInfo(dest).Length;
            if (size == 0) { try { File.Delete(dest); } catch { } return false; }

            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = originalPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                Category = "registry",
                Size = size
            });
            count++;
            bytes += size;
            return true;
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"  reg save {regKey}: {ex.Message}");
            return false;
        }
    }

    private static bool TryCaptureViaBackup(string source, string dest, string originalPath,
        CollectionContext context, ref int count, ref long bytes)
    {
        try
        {
            FileHelper.BackupCopy(source, dest);
            var size = new FileInfo(dest).Length;
            if (size == 0) { try { File.Delete(dest); } catch { } return false; }

            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = originalPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                Category = "registry",
                Size = size
            });
            count++;
            bytes += size;
            return true;
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"  {Path.GetFileName(source)}: {ex.Message}");
            try { if (File.Exists(dest)) File.Delete(dest); } catch { }
            return false;
        }
    }
}
