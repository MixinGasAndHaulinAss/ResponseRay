using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class CrashDumpCollector : ICollector
{
    public string Name => "CrashDumps";
    public string Description => "Application crash dumps and minidumps from system, LocalDumps, and per-user paths";

    private const long MaxDumpSize = 500L * 1024 * 1024; // 500 MB cap per dump

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        var roots = new List<(string root, string label)>
        {
            (@"C:\Windows\Minidump", "minidump"),
            (@"C:\Windows\LiveKernelReports", "livekernel"),
            (@"C:\ProgramData\Microsoft\Windows\WER\ReportArchive", "wer_archive"),
            (@"C:\ProgramData\Microsoft\Windows\WER\ReportQueue", "wer_queue"),
            (@"C:\Windows\System32\config\systemprofile\AppData\Local\CrashDumps", "system_crashdumps"),
        };

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;
            roots.Add((Path.Combine(userDir, "AppData", "Local", "CrashDumps"), $"crashdumps_{username}"));
        }

        foreach (var (root, label) in roots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                try
                {
                    var size = new FileInfo(file).Length;
                    if (size > MaxDumpSize) continue;
                    var relPath = Path.GetRelativePath(root, file);
                    var rel = Path.Combine("artifacts", "crashdumps", label, relPath);
                    context.TryCaptureFile(file, rel, "crash_dump", ref count, ref bytes);
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
