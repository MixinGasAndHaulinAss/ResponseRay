using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class WmiCollector : ICollector
{
    public string Name => "WMIRepository";
    public string Description => "WMI Repository OBJECTS.DATA";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "artifacts", "wmi");
        Directory.CreateDirectory(destDir);

        var objectsDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "wbem", "Repository", "OBJECTS.DATA");

        if (!File.Exists(objectsDataPath))
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };

        try
        {
            var dest = Path.Combine(destDir, "OBJECTS.DATA");
            File.Copy(objectsDataPath, dest, overwrite: true);
            var size = new FileInfo(dest).Length;
            context.CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = objectsDataPath,
                RelativePath = Path.GetRelativePath(context.OutputDir, dest),
                Category = "wmi",
                Size = size
            });
            return new CollectorResult
            {
                CollectorName = Name,
                FilesCollected = 1,
                BytesCollected = size,
                Elapsed = sw.Elapsed
            };
        }
        catch (Exception ex)
        {
            return new CollectorResult { CollectorName = Name, Error = ex.Message, Elapsed = sw.Elapsed };
        }
    }
}
