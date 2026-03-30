using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using ResponseRayCollector.Models;
using ResponseRayCollector.Native;

namespace ResponseRayCollector.Collectors;

public class NetworkCollector : ICollector
{
    public string Name => "NetworkConnections";
    public string Description => "Active TCP/UDP connections with owning process";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var processNames = new Dictionary<int, string>();
        foreach (var p in Process.GetProcesses())
        {
            try { processNames[p.Id] = p.ProcessName; }
            catch { }
            finally { p.Dispose(); }
        }

        var connections = new List<NetworkConnection>();

        // TCP connections
        foreach (var row in GetTcpConnections())
        {
            connections.Add(new NetworkConnection
            {
                Protocol = "TCP",
                LocalAddress = NativeMethods.IpToString(row.LocalAddr),
                LocalPort = NativeMethods.NetworkToHostPort(row.LocalPort),
                RemoteAddress = NativeMethods.IpToString(row.RemoteAddr),
                RemotePort = NativeMethods.NetworkToHostPort(row.RemotePort),
                State = NativeMethods.TcpStateToString(row.State),
                Pid = row.OwningPid,
                ProcessName = processNames.GetValueOrDefault(row.OwningPid, ""),
                CollectionTimestamp = timestamp
            });
        }

        // UDP listeners
        foreach (var row in GetUdpListeners())
        {
            connections.Add(new NetworkConnection
            {
                Protocol = "UDP",
                LocalAddress = NativeMethods.IpToString(row.LocalAddr),
                LocalPort = NativeMethods.NetworkToHostPort(row.LocalPort),
                RemoteAddress = "*",
                RemotePort = 0,
                State = "LISTENING",
                Pid = row.OwningPid,
                ProcessName = processNames.GetValueOrDefault(row.OwningPid, ""),
                CollectionTimestamp = timestamp
            });
        }

        var dest = Path.Combine(destDir, "connections.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(connections, new JsonSerializerOptions { WriteIndented = true }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = connections.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static List<NativeMethods.MibTcpRowOwnerPid> GetTcpConnections()
    {
        var rows = new List<NativeMethods.MibTcpRowOwnerPid>();
        int size = 0;
        NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2 /* AF_INET */,
            NativeMethods.TcpTableClass.OwnerPidAll);

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NativeMethods.GetExtendedTcpTable(buffer, ref size, true, 2,
                NativeMethods.TcpTableClass.OwnerPidAll) != 0)
                return rows;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<NativeMethods.MibTcpRowOwnerPid>();

            for (int i = 0; i < numEntries; i++)
            {
                rows.Add(Marshal.PtrToStructure<NativeMethods.MibTcpRowOwnerPid>(rowPtr));
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }

        return rows;
    }

    private static List<NativeMethods.MibUdpRowOwnerPid> GetUdpListeners()
    {
        var rows = new List<NativeMethods.MibUdpRowOwnerPid>();
        int size = 0;
        NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, true, 2 /* AF_INET */,
            NativeMethods.UdpTableClass.OwnerPid);

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NativeMethods.GetExtendedUdpTable(buffer, ref size, true, 2,
                NativeMethods.UdpTableClass.OwnerPid) != 0)
                return rows;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<NativeMethods.MibUdpRowOwnerPid>();

            for (int i = 0; i < numEntries; i++)
            {
                rows.Add(Marshal.PtrToStructure<NativeMethods.MibUdpRowOwnerPid>(rowPtr));
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }

        return rows;
    }
}
