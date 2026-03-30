using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Native;

namespace ResponseRayCollector.Collectors;

public class ArpCacheCollector : ICollector
{
    public string Name => "ARPCache";
    public string Description => "ARP table (IP-to-MAC mappings)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var entries = new List<ArpEntry>();

        int size = 0;
        NativeMethods.GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size == 0)
        {
            WriteEmpty(destDir, entries);
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NativeMethods.GetIpNetTable(buffer, ref size, false) != 0)
            {
                WriteEmpty(destDir, entries);
                return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };
            }

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<NativeMethods.MibIpNetRow>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MibIpNetRow>(rowPtr);
                entries.Add(new ArpEntry
                {
                    IpAddress = new IPAddress(row.Addr).ToString(),
                    MacAddress = FormatMac(row.PhysAddr, row.PhysAddrLen),
                    Type = ArpTypeToString(row.Type),
                    InterfaceIndex = row.Index,
                    CollectionTimestamp = timestamp
                });
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }

        var dest = Path.Combine(destDir, "arp_cache.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = entries.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void WriteEmpty(string destDir, List<ArpEntry> entries)
    {
        File.WriteAllText(Path.Combine(destDir, "arp_cache.json"),
            JsonSerializer.Serialize(entries));
    }

    private static string FormatMac(byte[] addr, int len)
    {
        if (addr == null || len <= 0) return "";
        return string.Join("-", addr.Take(len).Select(b => b.ToString("X2")));
    }

    private static string ArpTypeToString(int type) => type switch
    {
        1 => "Other",
        2 => "Invalid",
        3 => "Dynamic",
        4 => "Static",
        _ => $"Unknown({type})"
    };
}
