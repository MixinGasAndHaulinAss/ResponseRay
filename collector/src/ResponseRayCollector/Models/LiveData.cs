using System.Text.Json.Serialization;

namespace ResponseRayCollector.Models;

public class ProcessInfo
{
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("ppid")] public int ParentPid { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("command_line")] public string CommandLine { get; set; } = "";
    [JsonPropertyName("user")] public string User { get; set; } = "";
    [JsonPropertyName("start_time")] public string? StartTime { get; set; }
    [JsonPropertyName("md5")] public string Md5 { get; set; } = "";
    [JsonPropertyName("modules")] public List<string>? Modules { get; set; }
    [JsonPropertyName("memory_mb")] public double MemoryMb { get; set; }
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class NetworkConnection
{
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "";
    [JsonPropertyName("local_address")] public string LocalAddress { get; set; } = "";
    [JsonPropertyName("local_port")] public int LocalPort { get; set; }
    [JsonPropertyName("remote_address")] public string RemoteAddress { get; set; } = "";
    [JsonPropertyName("remote_port")] public int RemotePort { get; set; }
    [JsonPropertyName("state")] public string State { get; set; } = "";
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("process_name")] public string ProcessName { get; set; } = "";
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class DnsCacheEntry
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("data")] public string Data { get; set; } = "";
    [JsonPropertyName("ttl")] public int Ttl { get; set; }
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class ArpEntry
{
    [JsonPropertyName("ip_address")] public string IpAddress { get; set; } = "";
    [JsonPropertyName("mac_address")] public string MacAddress { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("interface_index")] public int InterfaceIndex { get; set; }
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class RouteEntry
{
    [JsonPropertyName("destination")] public string Destination { get; set; } = "";
    [JsonPropertyName("netmask")] public string Netmask { get; set; } = "";
    [JsonPropertyName("gateway")] public string Gateway { get; set; } = "";
    [JsonPropertyName("interface_address")] public string InterfaceAddress { get; set; } = "";
    [JsonPropertyName("metric")] public int Metric { get; set; }
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class LogonSessionInfo
{
    [JsonPropertyName("logon_id")] public string LogonId { get; set; } = "";
    [JsonPropertyName("username")] public string Username { get; set; } = "";
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("sid")] public string Sid { get; set; } = "";
    [JsonPropertyName("logon_type")] public string LogonType { get; set; } = "";
    [JsonPropertyName("logon_time")] public string? LogonTime { get; set; }
    [JsonPropertyName("auth_package")] public string AuthPackage { get; set; } = "";
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class UserAccountInfo
{
    [JsonPropertyName("username")] public string Username { get; set; } = "";
    [JsonPropertyName("full_name")] public string FullName { get; set; } = "";
    [JsonPropertyName("sid")] public string Sid { get; set; } = "";
    [JsonPropertyName("is_disabled")] public bool IsDisabled { get; set; }
    [JsonPropertyName("is_locked")] public bool IsLocked { get; set; }
    [JsonPropertyName("last_logon")] public string? LastLogon { get; set; }
    [JsonPropertyName("password_last_set")] public string? PasswordLastSet { get; set; }
    [JsonPropertyName("groups")] public List<string> Groups { get; set; } = new();
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class ServiceInfo
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("display_name")] public string DisplayName { get; set; } = "";
    [JsonPropertyName("binary_path")] public string BinaryPath { get; set; } = "";
    [JsonPropertyName("start_type")] public string StartType { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("account")] public string Account { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class StartupItemInfo
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("command")] public string Command { get; set; } = "";
    [JsonPropertyName("location")] public string Location { get; set; } = "";
    [JsonPropertyName("user")] public string User { get; set; } = "";
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}

public class DeviceInfo
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("manufacturer")] public string Manufacturer { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("class_name")] public string ClassName { get; set; } = "";
    [JsonPropertyName("serial_number")] public string SerialNumber { get; set; } = "";
    [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
}
