using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class FileSystemCollector : ICollector
{
    public string Name => "FileSystem";
    public string Description => "Filesystem enumeration with MACB timestamps (fallback when $MFT unavailable)";

    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\System Volume Information",
    };

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var dest = Path.Combine(destDir, "filesystem.jsonl");
        int count = 0;

        using (var writer = new StreamWriter(dest, false, System.Text.Encoding.UTF8, 65536))
        {
            var options = new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

            foreach (var entry in EnumerateFileSystem(@"C:\", timestamp))
            {
                writer.WriteLine(JsonSerializer.Serialize(entry, options));
                count++;

                if (count % 100000 == 0)
                    ConsoleOutput.Status($"  Enumerated {count:N0} files...");
            }
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static IEnumerable<FileSystemEntry> EnumerateFileSystem(string root, string collectionTimestamp)
    {
        var dirsToProcess = new Stack<string>();
        dirsToProcess.Push(root);

        while (dirsToProcess.Count > 0)
        {
            var currentDir = dirsToProcess.Pop();

            if (SkipDirs.Any(s => currentDir.StartsWith(s, StringComparison.OrdinalIgnoreCase)))
                continue;

            // Enumerate files in current directory
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(currentDir); }
            catch { continue; }

            foreach (var filePath in files)
            {
                FileSystemEntry? entry = null;
                try
                {
                    var fi = new FileInfo(filePath);
                    entry = new FileSystemEntry
                    {
                        Path = filePath,
                        Name = fi.Name,
                        Size = fi.Length,
                        IsDirectory = false,
                        Created = fi.CreationTimeUtc.ToString("o"),
                        Modified = fi.LastWriteTimeUtc.ToString("o"),
                        Accessed = fi.LastAccessTimeUtc.ToString("o"),
                        Extension = fi.Extension,
                        CollectionTimestamp = collectionTimestamp
                    };
                }
                catch { /* skip inaccessible files */ }

                if (entry != null) yield return entry;
            }

            // Enumerate subdirectories
            IEnumerable<string> subdirs;
            try { subdirs = Directory.EnumerateDirectories(currentDir); }
            catch { continue; }

            foreach (var subdir in subdirs)
            {
                FileSystemEntry? dirEntry = null;
                try
                {
                    var di = new DirectoryInfo(subdir);
                    dirEntry = new FileSystemEntry
                    {
                        Path = subdir,
                        Name = di.Name,
                        Size = 0,
                        IsDirectory = true,
                        Created = di.CreationTimeUtc.ToString("o"),
                        Modified = di.LastWriteTimeUtc.ToString("o"),
                        Accessed = di.LastAccessTimeUtc.ToString("o"),
                        CollectionTimestamp = collectionTimestamp
                    };
                }
                catch { /* skip inaccessible dirs */ }

                if (dirEntry != null) yield return dirEntry;

                dirsToProcess.Push(subdir);
            }
        }
    }

    private class FileSystemEntry
    {
        [JsonPropertyName("path")] public string Path { get; set; } = "";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("size")] public long Size { get; set; }
        [JsonPropertyName("is_directory")] public bool IsDirectory { get; set; }
        [JsonPropertyName("created")] public string Created { get; set; } = "";
        [JsonPropertyName("modified")] public string Modified { get; set; } = "";
        [JsonPropertyName("accessed")] public string Accessed { get; set; } = "";
        [JsonPropertyName("extension")] public string? Extension { get; set; }
        [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
    }
}
