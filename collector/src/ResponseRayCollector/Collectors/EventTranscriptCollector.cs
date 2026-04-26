using System.Diagnostics;

namespace ResponseRayCollector.Collectors;

public class EventTranscriptCollector : ICollector
{
    public string Name => "EventTranscript";
    public string Description => "Windows DiagTrack EventTranscript.db (UTC telemetry containing app exec history)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        var paths = new[]
        {
            @"C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db",
            @"C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db-wal",
            @"C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db-shm",
        };

        foreach (var path in paths)
        {
            var rel = Path.Combine("artifacts", "eventtranscript", Path.GetFileName(path));
            context.TryCaptureFile(path, rel, "event_transcript", ref count, ref bytes);
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
