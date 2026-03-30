using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class EventLogCollector : ICollector
{
    public string Name => "EventLogs";
    public string Description => "Windows Event Log files (.evtx)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "evtx");
        Directory.CreateDirectory(destDir);

        var logsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "winevt", "Logs");

        if (!Directory.Exists(logsDir))
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        int count = 0;
        long bytes = 0;

        foreach (var file in Directory.EnumerateFiles(logsDir, "*.evtx"))
        {
            try
            {
                var fileName = Path.GetFileName(file);
                var dest = Path.Combine(destDir, fileName);
                File.Copy(file, dest, overwrite: true);
                var size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = file,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "evtx",
                    Size = size
                });
                count++;
                bytes += size;
            }
            catch { /* skip inaccessible evtx files */ }
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
