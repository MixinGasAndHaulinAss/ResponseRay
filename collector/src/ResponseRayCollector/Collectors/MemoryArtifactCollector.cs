using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Captures hibernation, page, and swap files when --include-memory is specified.
/// These can be very large; gated to avoid surprising the operator.
/// </summary>
public class MemoryArtifactCollector : ICollector
{
    public string Name => "MemoryArtifacts";
    public string Description => "hiberfil.sys, pagefile.sys, swapfile.sys (opt-in via --include-memory)";

    private static readonly string[] Files =
    [
        @"C:\hiberfil.sys",
        @"C:\pagefile.sys",
        @"C:\swapfile.sys",
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        if (!context.IncludeMemory)
        {
            ConsoleOutput.Status("  --include-memory not set; skipping memory artifacts");
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };
        }

        foreach (var path in Files)
        {
            ConsoleOutput.Info($"  Copying {path} (this may take a while)...");
            var rel = Path.Combine("artifacts", "memory", Path.GetFileName(path));
            context.TryCaptureFile(path, rel, "memory_artifact", ref count, ref bytes);
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
