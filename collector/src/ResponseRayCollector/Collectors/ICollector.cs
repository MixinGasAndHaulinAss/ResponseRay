namespace ResponseRayCollector.Collectors;

public interface ICollector
{
    string Name { get; }
    string Description { get; }
    CollectorResult Collect(CollectionContext context);
}

public class CollectionContext
{
    public required string OutputDir { get; init; }
    public required string VssRoot { get; init; }
    public required string Hostname { get; init; }
    public required DateTime CollectionTime { get; init; }
    public List<CollectedFileEntry> CollectedFiles { get; } = new();
}

public class CollectedFileEntry
{
    public required string OriginalPath { get; init; }
    public required string RelativePath { get; init; }
    public required string Category { get; init; }
    public long Size { get; init; }
}

public class CollectorResult
{
    public required string CollectorName { get; init; }
    public int FilesCollected { get; init; }
    public long BytesCollected { get; init; }
    public TimeSpan Elapsed { get; init; }
    public string? Error { get; init; }
}
