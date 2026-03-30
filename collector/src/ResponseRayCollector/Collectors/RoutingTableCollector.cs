using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Native;

namespace ResponseRayCollector.Collectors;

public class RoutingTableCollector : ICollector
{
    public string Name => "RoutingTable";
    public string Description => "IP routing table";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var entries = new List<RouteEntry>();

        int size = 0;
        NativeMethods.GetIpForwardTable(IntPtr.Zero, ref size, false);
        if (size == 0)
        {
            WriteResult(destDir, entries);
            return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NativeMethods.GetIpForwardTable(buffer, ref size, false) != 0)
            {
                WriteResult(destDir, entries);
                return new CollectorResult { CollectorName = Name, Elapsed = sw.Elapsed };
            }

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<NativeMethods.MibIpForwardRow>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MibIpForwardRow>(rowPtr);
                entries.Add(new RouteEntry
                {
                    Destination = new IPAddress(row.Dest).ToString(),
                    Netmask = new IPAddress(row.Mask).ToString(),
                    Gateway = new IPAddress(row.NextHop).ToString(),
                    InterfaceAddress = $"if{row.IfIndex}",
                    Metric = row.Metric1,
                    CollectionTimestamp = timestamp
                });
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }

        WriteResult(destDir, entries);

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = entries.Count,
            BytesCollected = new FileInfo(Path.Combine(destDir, "routing_table.json")).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void WriteResult(string destDir, List<RouteEntry> entries)
    {
        File.WriteAllText(Path.Combine(destDir, "routing_table.json"),
            JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }));
    }
}
