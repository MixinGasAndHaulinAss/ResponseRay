using System.Diagnostics;

namespace ResponseRayCollector.Collectors;

public class HostsCollector : ICollector
{
    public string Name => "Hosts";
    public string Description => "Hosts file, networks file, lmhosts, and other static name resolution files";

    private static readonly string[] Files =
    [
        @"C:\Windows\System32\drivers\etc\hosts",
        @"C:\Windows\System32\drivers\etc\networks",
        @"C:\Windows\System32\drivers\etc\protocol",
        @"C:\Windows\System32\drivers\etc\services",
        @"C:\Windows\System32\drivers\etc\hosts.ics",
        @"C:\Windows\System32\drivers\etc\lmhosts.sam",
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        foreach (var path in Files)
        {
            var rel = Path.Combine("artifacts", "hosts", Path.GetFileName(path));
            context.TryCaptureFile(path, rel, "hosts", ref count, ref bytes);
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
