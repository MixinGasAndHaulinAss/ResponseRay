using System.Runtime.InteropServices;
using System.Net;

namespace ResponseRayCollector.Native;

public static class NativeMethods
{
    // --- TCP/UDP Tables ---

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, TcpTableClass tableClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, UdpTableClass tableClass, uint reserved = 0);

    public enum TcpTableClass { OwnerPidAll = 5 }
    public enum UdpTableClass { OwnerPid = 1 }

    [StructLayout(LayoutKind.Sequential)]
    public struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public int OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public int OwningPid;
    }

    public static string TcpStateToString(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"UNKNOWN({state})"
    };

    public static string IpToString(uint addr) => new IPAddress(addr).ToString();

    public static ushort NetworkToHostPort(uint port) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(port & 0xFFFF));

    // --- ARP Table ---

    [DllImport("iphlpapi.dll")]
    public static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [StructLayout(LayoutKind.Sequential)]
    public struct MibIpNetRow
    {
        public int Index;
        public int PhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PhysAddr;
        public uint Addr;
        public int Type;
    }

    // --- IP Forward (Routing) Table ---

    [DllImport("iphlpapi.dll")]
    public static extern int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

    [StructLayout(LayoutKind.Sequential)]
    public struct MibIpForwardRow
    {
        public uint Dest;
        public uint Mask;
        public int Policy;
        public uint NextHop;
        public int IfIndex;
        public int Type;
        public int Proto;
        public int Age;
        public int NextHopAS;
        public int Metric1;
        public int Metric2;
        public int Metric3;
        public int Metric4;
        public int Metric5;
    }

    // --- DNS Cache ---

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", SetLastError = true)]
    public static extern bool DnsGetCacheDataTable(out IntPtr ppEntry);

    [DllImport("dnsapi.dll", EntryPoint = "DnsFree", SetLastError = true)]
    public static extern void DnsFree(IntPtr pData, int freeType);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DnsCacheEntry
    {
        public IntPtr Next;
        public IntPtr Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
    }

    // DNS record types
    public static string DnsTypeToString(ushort type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        _ => $"TYPE{type}"
    };

    // --- DnsQuery for resolving cached entries ---

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DnsQuery(
        string lpstrName,
        ushort wType,
        uint options,
        IntPtr pExtra,
        out IntPtr ppQueryResults,
        IntPtr pReserved);

    [DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
    public static extern void DnsRecordListFree(IntPtr pRecordList, int freeType);

    public const uint DNS_QUERY_NO_WIRE_QUERY = 0x00000010; // cache only, no network
    public const int DnsFreeRecordList = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DnsRecordA
    {
        public IntPtr Next;
        public IntPtr Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
        public uint Ttl;
        public uint Reserved;
        public uint IpAddress; // for A records
    }
}
