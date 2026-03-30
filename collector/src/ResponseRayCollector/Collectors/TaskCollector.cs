using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class TaskCollector : ICollector
{
    public string Name => "ScheduledTasks";
    public string Description => "Scheduled task XML files";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "tasks");
        Directory.CreateDirectory(destDir);

        var tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");
        if (!Directory.Exists(tasksDir))
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        int count = 0;
        long bytes = 0;

        foreach (var file in Directory.EnumerateFiles(tasksDir, "*", SearchOption.AllDirectories))
        {
            try
            {
                var relativePath = Path.GetRelativePath(tasksDir, file);
                var dest = Path.Combine(destDir, relativePath);
                FileHelper.SafeCopy(file, dest);
                var size = new FileInfo(dest).Length;
                context.CollectedFiles.Add(new CollectedFileEntry
                {
                    OriginalPath = file,
                    RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                    Category = "tasks",
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
