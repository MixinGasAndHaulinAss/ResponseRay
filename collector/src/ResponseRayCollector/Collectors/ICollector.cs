using ResponseRayCollector.Utils;

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
    public required string Hostname { get; init; }
    public required DateTime CollectionTime { get; init; }

    /// <summary>
    /// Path to a Volume Shadow Copy of C:\ if one was created (e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\).
    /// Collectors that read locked files should prefer this when available and fall back to the live path on failure.
    /// </summary>
    public string? VssShadowPath { get; set; }

    public bool IncludeMemory { get; set; }

    public List<CollectedFileEntry> CollectedFiles { get; } = new();

    /// <summary>
    /// Tries to capture a single file from the live system (using VSS shadow path when available)
    /// into <paramref name="destRelative"/> beneath the output dir. Returns true on success.
    /// </summary>
    public bool TryCaptureFile(string livePath, string destRelative, string category,
        ref int count, ref long bytes)
    {
        try
        {
            var source = ResolveSourcePath(livePath);
            if (!File.Exists(source) && !FileHelper.FileExistsViaBackup(source))
            {
                if (string.IsNullOrEmpty(VssShadowPath)) return false;
                source = livePath;
                if (!File.Exists(source) && !FileHelper.FileExistsViaBackup(source)) return false;
            }

            var dest = Path.Combine(OutputDir, destRelative);
            FileHelper.BackupCopy(source, dest);
            var size = new FileInfo(dest).Length;
            if (size == 0) { try { File.Delete(dest); } catch { } return false; }

            CollectedFiles.Add(new CollectedFileEntry
            {
                OriginalPath = livePath,
                RelativePath = destRelative.Replace('\\', '/'),
                Category = category,
                Size = size
            });
            count++;
            bytes += size;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Resolves a live filesystem path to the equivalent path under the VSS shadow when available.
    /// e.g. C:\Windows\System32\config\SAM -> \\?\GLOBALROOT\...\Windows\System32\config\SAM
    /// </summary>
    public string ResolveSourcePath(string livePath)
    {
        if (string.IsNullOrEmpty(VssShadowPath))
            return livePath;

        if (livePath.Length < 3 || livePath[1] != ':' || livePath[2] != '\\')
            return livePath;

        var systemDrive = (Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1)).ToUpperInvariant();
        if (char.ToUpperInvariant(livePath[0]).ToString() != systemDrive)
            return livePath;

        return Path.Combine(VssShadowPath, livePath.Substring(3));
    }
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
