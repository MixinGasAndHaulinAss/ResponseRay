using System.Text.Json;
using System.Text.Json.Serialization;

namespace ResponseRayCollector.Models;

public class CollectionManifest
{
    [JsonPropertyName("collector_version")] public string CollectorVersion { get; set; } = "";
    [JsonPropertyName("platform")] public string Platform { get; set; } = "windows";
    [JsonPropertyName("hostname")] public string Hostname { get; set; } = "";
    [JsonPropertyName("os_version")] public string OsVersion { get; set; } = "";
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("vss_used")] public bool VssUsed { get; set; }
    [JsonPropertyName("vss_path")] public string? VssPath { get; set; }
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
    [JsonPropertyName("collection_duration_seconds")] public double CollectionDurationSeconds { get; set; }
    [JsonPropertyName("user_profiles")] public List<string> UserProfiles { get; set; } = new();
    [JsonPropertyName("total_files")] public int TotalFiles { get; set; }
    [JsonPropertyName("total_bytes")] public long TotalBytes { get; set; }
    [JsonPropertyName("collector_results")] public List<CollectorResultEntry> CollectorResults { get; set; } = new();
    [JsonPropertyName("files")] public List<FileEntry> Files { get; set; } = new();

    public class CollectorResultEntry
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("files_collected")] public int FilesCollected { get; set; }
        [JsonPropertyName("bytes_collected")] public long BytesCollected { get; set; }
        [JsonPropertyName("elapsed_ms")] public long ElapsedMs { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    public class FileEntry
    {
        [JsonPropertyName("original_path")] public string OriginalPath { get; set; } = "";
        [JsonPropertyName("relative_path")] public string RelativePath { get; set; } = "";
        [JsonPropertyName("category")] public string Category { get; set; } = "";
        [JsonPropertyName("size")] public long Size { get; set; }
    }

    public void Save(string path)
    {
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
        File.WriteAllText(path, json);
    }
}
