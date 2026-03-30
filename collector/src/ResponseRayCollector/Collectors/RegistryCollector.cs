using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class RegistryCollector : ICollector
{
    public string Name => "Registry";
    public string Description => "Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve)";

    private static readonly string[] SystemHives = ["SAM", "SYSTEM", "SOFTWARE", "SECURITY"];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "registry");
        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        var configDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "config");

        foreach (var hive in SystemHives)
        {
            var src = Path.Combine(configDir, hive);
            var dest = Path.Combine(destDir, hive);
            if (TryCapture(src, dest, src, "registry", context, ref count, ref bytes))
                ConsoleOutput.Status($"  {hive}: captured");
        }

        // Amcache
        var amcachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "AppCompat", "Programs", "Amcache.hve");
        var amcacheDest = Path.Combine(destDir, "Amcache.hve");
        if (TryCapture(amcachePath, amcacheDest, amcachePath, "registry", context, ref count, ref bytes))
            ConsoleOutput.Status("  Amcache.hve: captured");

        // Per-user hives
        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir);

            var ntuserPath = Path.Combine(userDir, "NTUSER.DAT");
            var ntuserDest = Path.Combine(destDir, $"{username}_NTUSER.DAT");
            if (TryCapture(ntuserPath, ntuserDest, ntuserPath, "registry", context, ref count, ref bytes))
                ConsoleOutput.Status($"  {username} NTUSER.DAT: captured");

            var usrClassPath = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat");
            var usrClassDest = Path.Combine(destDir, $"{username}_UsrClass.dat");
            if (TryCapture(usrClassPath, usrClassDest, usrClassPath, "registry", context, ref count, ref bytes))
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

    private static bool TryCapture(string source, string dest, string originalPath,
        string category, CollectionContext context, ref int count, ref long bytes)
    {
        if (!File.Exists(source))
            return false;

        try
        {
            FileHelper.BackupCopy(source, dest);
            var size = new FileInfo(dest).Length;
            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = originalPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                Category = category,
                Size = size
            });
            count++;
            bytes += size;
            return true;
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"  {Path.GetFileName(source)}: {ex.Message}");
            return false;
        }
    }
}
