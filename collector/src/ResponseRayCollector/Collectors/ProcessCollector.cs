using System.Diagnostics;
using System.Management;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class ProcessCollector : ICollector
{
    public string Name => "Processes";
    public string Description => "Running process snapshot with hashes, modules, and memory";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var processes = new List<ProcessInfo>();
        var wmiData = GetWmiProcessData();
        var hashCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var info = new ProcessInfo
                {
                    Pid = proc.Id,
                    Name = proc.ProcessName,
                    CollectionTimestamp = timestamp
                };

                if (wmiData.TryGetValue(proc.Id, out var wmi))
                {
                    info.ParentPid = wmi.ParentPid;
                    info.CommandLine = wmi.CommandLine;
                    info.Path = wmi.ExecutablePath;
                    info.User = wmi.Owner;
                }

                try { info.StartTime = proc.StartTime.ToUniversalTime().ToString("o"); } catch { }
                try { info.MemoryMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024), 1); } catch { }

                // Hash with cache to avoid re-hashing the same binary
                if (!string.IsNullOrEmpty(info.Path) && File.Exists(info.Path))
                {
                    if (!hashCache.TryGetValue(info.Path, out var hash))
                    {
                        hash = FileHelper.ComputeMd5(info.Path);
                        hashCache[info.Path] = hash;
                    }
                    info.Md5 = hash;
                }

                // Loaded modules (DLLs)
                try
                {
                    var modules = new List<string>();
                    foreach (ProcessModule mod in proc.Modules)
                    {
                        try { modules.Add(mod.FileName); }
                        catch { }
                    }
                    if (modules.Count > 0)
                        info.Modules = modules;
                }
                catch { /* access denied for system processes */ }

                processes.Add(info);
            }
            catch { /* skip inaccessible processes */ }
            finally { proc.Dispose(); }
        }

        var dest = Path.Combine(destDir, "processes.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(processes, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = processes.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static Dictionary<int, WmiProcessInfo> GetWmiProcessData()
    {
        var result = new Dictionary<int, WmiProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, CommandLine, ExecutablePath FROM Win32_Process");
            foreach (var obj in searcher.Get())
            {
                var pid = Convert.ToInt32(obj["ProcessId"]);
                var info = new WmiProcessInfo
                {
                    ParentPid = Convert.ToInt32(obj["ParentProcessId"] ?? 0),
                    CommandLine = obj["CommandLine"]?.ToString() ?? "",
                    ExecutablePath = obj["ExecutablePath"]?.ToString() ?? ""
                };

                try
                {
                    var outParams = ((ManagementObject)obj).InvokeMethod("GetOwner", null, null);
                    if (outParams != null)
                    {
                        var domain = outParams["Domain"]?.ToString() ?? "";
                        var user = outParams["User"]?.ToString() ?? "";
                        info.Owner = string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}";
                    }
                }
                catch { }

                result[pid] = info;
            }
        }
        catch { }
        return result;
    }

    private class WmiProcessInfo
    {
        public int ParentPid;
        public string CommandLine = "";
        public string ExecutablePath = "";
        public string Owner = "";
    }
}
