using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class RecycleBinCollector : ICollector
{
    public string Name => "RecycleBin";
    public string Description => "Recycle Bin $I metadata files";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "recyclebin");
        Directory.CreateDirectory(destDir);

        var recycleBinDir = @"C:\$Recycle.Bin";
        if (!Directory.Exists(recycleBinDir))
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        int count = 0;
        long bytes = 0;

        try
        {
            foreach (var sidDir in Directory.EnumerateDirectories(recycleBinDir))
            {
                var sid = Path.GetFileName(sidDir);
                foreach (var file in Directory.EnumerateFiles(sidDir, "$I*"))
                {
                    try
                    {
                        var dest = Path.Combine(destDir, $"{sid}_{Path.GetFileName(file)}");
                        File.Copy(file, dest, overwrite: true);
                        var size = new FileInfo(dest).Length;
                        context.CollectedFiles.Add(new CollectedFileEntry
                        {
                            OriginalPath = file,
                            RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                            Category = "recyclebin",
                            Size = size
                        });
                        count++;
                        bytes += size;
                    }
                    catch { /* skip inaccessible */ }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            ConsoleOutput.Warning("Recycle Bin: access denied to some SID directories");
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
