using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class WerFileCollector : ICollector
{
    public string Name => "WerFiles";
    public string Description => "Windows Error Reporting (.wer) report metadata files";

    private const long MaxFileSize = 50L * 1024 * 1024;

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        var roots = new List<string>
        {
            @"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
            @"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
            @"C:\ProgramData\Microsoft\Windows\WER\Temp",
        };

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            roots.Add(Path.Combine(userDir, "AppData", "Local", "Microsoft", "Windows", "WER"));
        }

        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var file in Directory.EnumerateFiles(root, "*.wer", SearchOption.AllDirectories))
            {
                try
                {
                    if (new FileInfo(file).Length > MaxFileSize) continue;
                    var relPath = Path.GetRelativePath(root, file);
                    var rel = Path.Combine("artifacts", "wer", Path.GetFileName(root), relPath);
                    context.TryCaptureFile(file, rel, "wer", ref count, ref bytes);
                }
                catch { }
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
}
