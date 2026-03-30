using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Native;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class DnsCacheCollector : ICollector
{
    public string Name => "DNSCache";
    public string Description => "DNS resolver cache entries via DnsGetCacheDataTable";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var entries = new List<DnsCacheEntry>();

        try
        {
            if (NativeMethods.DnsGetCacheDataTable(out var pEntry))
            {
                var current = pEntry;
                while (current != IntPtr.Zero)
                {
                    var entry = Marshal.PtrToStructure<NativeMethods.DnsCacheEntry>(current);
                    var name = entry.Name != IntPtr.Zero ? Marshal.PtrToStringUni(entry.Name) ?? "" : "";

                    if (!string.IsNullOrEmpty(name))
                    {
                        var resolvedIp = "";
                        uint ttl = 0;

                        // Query the cache for this entry's resolved data
                        if (entry.Type > 0)
                        {
                            try
                            {
                                var hr = NativeMethods.DnsQuery(name, entry.Type,
                                    NativeMethods.DNS_QUERY_NO_WIRE_QUERY,
                                    IntPtr.Zero, out var pResults, IntPtr.Zero);

                                if (hr == 0 && pResults != IntPtr.Zero)
                                {
                                    var ips = new List<string>();
                                    var recPtr = pResults;
                                    while (recPtr != IntPtr.Zero)
                                    {
                                        var rec = Marshal.PtrToStructure<NativeMethods.DnsRecordA>(recPtr);
                                        ttl = rec.Ttl;

                                        if (rec.Type == 1) // A record
                                            ips.Add(new IPAddress(rec.IpAddress).ToString());
                                        else if (rec.Type == 28 && rec.DataLength >= 16) // AAAA
                                        {
                                            var addrBytes = new byte[16];
                                            Marshal.Copy(recPtr + Marshal.OffsetOf<NativeMethods.DnsRecordA>("IpAddress").ToInt32(), addrBytes, 0, 16);
                                            ips.Add(new IPAddress(addrBytes).ToString());
                                        }
                                        else if (rec.Type == 5) // CNAME
                                        {
                                            var cnamePtr = Marshal.ReadIntPtr(recPtr + Marshal.OffsetOf<NativeMethods.DnsRecordA>("IpAddress").ToInt32());
                                            if (cnamePtr != IntPtr.Zero)
                                                ips.Add(Marshal.PtrToStringUni(cnamePtr) ?? "");
                                        }

                                        recPtr = rec.Next;
                                    }
                                    resolvedIp = string.Join(", ", ips);
                                    NativeMethods.DnsRecordListFree(pResults, NativeMethods.DnsFreeRecordList);
                                }
                            }
                            catch { /* skip unresolvable entries */ }
                        }

                        entries.Add(new DnsCacheEntry
                        {
                            Name = name,
                            Type = NativeMethods.DnsTypeToString(entry.Type),
                            Data = resolvedIp,
                            Ttl = (int)ttl,
                            CollectionTimestamp = timestamp
                        });
                    }

                    current = entry.Next;
                }
            }
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"DNS cache (native API): {ex.Message}");

            // Fallback to Get-DnsClientCache PowerShell cmdlet
            try
            {
                entries.AddRange(FallbackPowerShell(timestamp));
            }
            catch (Exception ex2)
            {
                ConsoleOutput.Warning($"DNS cache (PowerShell fallback): {ex2.Message}");
            }
        }

        var dest = Path.Combine(destDir, "dns_cache.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = entries.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static List<DnsCacheEntry> FallbackPowerShell(string timestamp)
    {
        var entries = new List<DnsCacheEntry>();
        using var proc = new Process();
        proc.StartInfo = new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = "-NoProfile -Command \"Get-DnsClientCache | Select-Object Entry,RecordType,TimeToLive,Data | ConvertTo-Json -Compress\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        proc.Start();
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(30_000);

        if (string.IsNullOrWhiteSpace(output)) return entries;

        using var doc = JsonDocument.Parse(output);
        var root = doc.RootElement;

        // Could be array or single object
        var elements = root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray()
            : new[] { root }.AsEnumerable().GetEnumerator() as IEnumerable<JsonElement> ?? [];

        foreach (var el in elements)
        {
            entries.Add(new DnsCacheEntry
            {
                Name = el.TryGetProperty("Entry", out var e) ? e.GetString() ?? "" : "",
                Type = el.TryGetProperty("RecordType", out var t) ? t.ToString() : "",
                Data = el.TryGetProperty("Data", out var d) ? d.GetString() ?? "" : "",
                Ttl = el.TryGetProperty("TimeToLive", out var ttl) && ttl.ValueKind == JsonValueKind.Number ? ttl.GetInt32() : 0,
                CollectionTimestamp = timestamp
            });
        }
        return entries;
    }
}
