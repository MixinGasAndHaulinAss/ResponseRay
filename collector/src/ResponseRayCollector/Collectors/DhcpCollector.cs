using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class DhcpCollector : ICollector
{
    public string Name => "DHCP";
    public string Description => "DHCP server log files";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "dhcp");

        var dhcpDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "dhcp");
        if (!Directory.Exists(dhcpDir))
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        var logFiles = Directory.EnumerateFiles(dhcpDir, "DhcpSrvLog*.log").ToList();
        if (logFiles.Count == 0)
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        Directory.CreateDirectory(destDir);
        int count = 0;
        long bytes = 0;

        foreach (var file in logFiles)
        {
            try
            {
                var dest = Path.Combine(destDir, Path.GetFileName(file));
                File.Copy(file, dest, overwrite: true);
                var size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = file,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "dhcp",
                    Size = size
                });
                count++;
                bytes += size;
            }
            catch { /* skip inaccessible */ }
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = bytes,
            Elapsed = sw.Elapsed
        };
    }
}
