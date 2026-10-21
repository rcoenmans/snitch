using System;
using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace Snitch;

public static partial class NetworkHelper
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TCP_TABLE_CLASS tblClass,
        int reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcpConnectionEStats(
        IntPtr row,
        TCP_ESTATS_TYPE estatsType,
        IntPtr rw,
        uint rwVersion,
        uint rwSize,
        IntPtr ros,
        uint rosVersion,
        uint rosSize,
        IntPtr rod,
        uint rodVersion,
        uint rodSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcp6ConnectionEStats(
        IntPtr row,
        TCP_ESTATS_TYPE estatsType,
        IntPtr rw,
        uint rwVersion,
        uint rwSize,
        IntPtr ros,
        uint rosVersion,
        uint rosSize,
        IntPtr rod,
        uint rodVersion,
        uint rodSize);

    private enum TCP_ESTATS_TYPE
    {
        TcpConnectionEstatsSynOpts = 0,
        TcpConnectionEstatsData,
        TcpConnectionEstatsSndCong,
        TcpConnectionEstatsPath,
        TcpConnectionEstatsSendBuff,
        TcpConnectionEstatsRec,
        TcpConnectionEstatsObsRec,
        TcpConnectionEstatsBandwidth,
        TcpConnectionEstatsFineRtt,
        TcpConnectionEstatsMaximum
    }

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint remoteAddr;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public MIB_TCP6ROW_OWNER_PID[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW
    {
        public uint State;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_ROD_v0
    {
        public ulong DataBytesOut;
        public ulong DataSegsOut;
        public ulong DataBytesIn;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    private enum MibTcpState
    {
        CLOSED = 1,
        LISTEN = 2,
        SYN_SENT = 3,
        SYN_RCVD = 4,
        ESTAB = 5,
        FIN_WAIT1 = 6,
        FIN_WAIT2 = 7,
        CLOSE_WAIT = 8,
        CLOSING = 9,
        LAST_ACK = 10,
        TIME_WAIT = 11,
        DELETE_TCB = 12
    }

    private static uint ConvertHostPortToNetworkOrder(int port)
    {
        var networkPort = IPAddress.HostToNetworkOrder((short)port);
        return (uint)(ushort)networkPort;
    }

    private readonly record struct TcpConnectionStats(long BytesSent, long BytesReceived);

    private static TcpConnectionStats QueryTcpConnectionStats(IPEndPoint localEndPoint, IPEndPoint remoteEndPoint)
    {
        if (localEndPoint.Port == 0 || remoteEndPoint.Port == 0)
        {
            return default;
        }

        if (localEndPoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return TryQueryIpv4TcpConnectionStats(localEndPoint, remoteEndPoint, out var bytesSent, out var bytesReceived)
                ? new TcpConnectionStats(bytesSent, bytesReceived)
                : default;
        }

        return TryQueryIpv6TcpConnectionStats(localEndPoint, remoteEndPoint, out var bytesSentV6, out var bytesReceivedV6)
            ? new TcpConnectionStats(bytesSentV6, bytesReceivedV6)
            : default;
    }

    private static bool TryQueryIpv4TcpConnectionStats(IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, out long bytesSent, out long bytesReceived)
    {
        bytesSent = 0;
        bytesReceived = 0;

        var localAddressBytes = localEndPoint.Address.GetAddressBytes();
        var remoteAddressBytes = remoteEndPoint.Address.GetAddressBytes();

        if (localAddressBytes.Length != 4 || remoteAddressBytes.Length != 4)
        {
            return false;
        }

        var row = new MIB_TCPROW
        {
            dwState = (uint)MibTcpState.ESTAB,
            dwLocalAddr = BinaryPrimitives.ReadUInt32BigEndian(localAddressBytes),
            dwLocalPort = ConvertHostPortToNetworkOrder(localEndPoint.Port),
            dwRemoteAddr = BinaryPrimitives.ReadUInt32BigEndian(remoteAddressBytes),
            dwRemotePort = ConvertHostPortToNetworkOrder(remoteEndPoint.Port)
        };

        var rowPtr = Marshal.AllocHGlobal(Marshal.SizeOf<MIB_TCPROW>());
        var rodSize = (uint)Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
        var rodPtr = Marshal.AllocHGlobal((int)rodSize);

        try
        {
            Marshal.StructureToPtr(row, rowPtr, false);
            var result = GetPerTcpConnectionEStats(
                rowPtr,
                TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                0,
                0,
                rodPtr,
                0,
                rodSize);

            if (result != 0)
            {
                return false;
            }

            var stats = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
            bytesSent = (long)stats.DataBytesOut;
            bytesReceived = (long)stats.DataBytesIn;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rowPtr);
            Marshal.FreeHGlobal(rodPtr);
        }
    }

    private static bool TryQueryIpv6TcpConnectionStats(IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, out long bytesSent, out long bytesReceived)
    {
        bytesSent = 0;
        bytesReceived = 0;

        if (localEndPoint.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return false;
        }

        var row = new MIB_TCP6ROW
        {
            State = (uint)MibTcpState.ESTAB,
            LocalAddr = new byte[16],
            dwLocalScopeId = 0,
            dwLocalPort = ConvertHostPortToNetworkOrder(localEndPoint.Port),
            RemoteAddr = new byte[16],
            dwRemoteScopeId = 0,
            dwRemotePort = ConvertHostPortToNetworkOrder(remoteEndPoint.Port)
        };

        var localAddressBytes = localEndPoint.Address.GetAddressBytes();
        var remoteAddressBytes = remoteEndPoint.Address.GetAddressBytes();
        Array.Copy(localAddressBytes, row.LocalAddr, localAddressBytes.Length);
        Array.Copy(remoteAddressBytes, row.RemoteAddr, remoteAddressBytes.Length);

        var rowPtr = Marshal.AllocHGlobal(Marshal.SizeOf<MIB_TCP6ROW>());
        var rodSize = (uint)Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
        var rodPtr = Marshal.AllocHGlobal((int)rodSize);

        try
        {
            Marshal.StructureToPtr(row, rowPtr, false);
            var result = GetPerTcp6ConnectionEStats(
                rowPtr,
                TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                0,
                0,
                rodPtr,
                0,
                rodSize);

            if (result != 0)
            {
                return false;
            }

            var stats = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
            bytesSent = (long)stats.DataBytesOut;
            bytesReceived = (long)stats.DataBytesIn;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rowPtr);
            Marshal.FreeHGlobal(rodPtr);
        }
    }
}
