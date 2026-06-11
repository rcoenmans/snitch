using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Snitch;

public static class NetworkHelper
{
    private const uint ErrorInsufficientBuffer = 122;
    private static readonly ConcurrentDictionary<IPAddress, string> DnsCache = new();
    private static readonly TimeSpan DnsLookupTimeout = TimeSpan.FromMilliseconds(300);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TCP_TABLE_CLASS tblClass,
        int reserved = 0);

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

    public static List<TcpConnectionInfo> GetAllTcpConnections()
    {
        var connections = new List<TcpConnectionInfo>();
        connections.AddRange(GetIpv4TcpConnections());
        connections.AddRange(GetIpv6TcpConnections());

        return connections;
    }

    private static List<TcpConnectionInfo> GetIpv4TcpConnections()
    {
        var connections = new List<TcpConnectionInfo>();
        int bufferSize = 0;

        uint initialResult = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, (int)AddressFamily.InterNetwork,
            TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

        if (initialResult != 0 && initialResult != ErrorInsufficientBuffer)
        {
            throw new Win32Exception((int)initialResult, "Failed to size TCP table buffer.");
        }

        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true,
                (int)AddressFamily.InterNetwork, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

            if (result != 0)
            {
                throw new Win32Exception((int)result, "Failed to get TCP table.");
            }

            var table = Marshal.PtrToStructure<MIB_TCPTABLE_OWNER_PID>(tcpTablePtr);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            IntPtr rowPtr = tcpTablePtr + Marshal.SizeOf<uint>();

            for (int i = 0; i < table.dwNumEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                var localEndPoint = new IPEndPoint(new IPAddress(row.localAddr), (row.localPort1 << 8) + row.localPort2);
                var remoteEndPoint = new IPEndPoint(new IPAddress(row.remoteAddr), (row.remotePort1 << 8) + row.remotePort2);

                GetProcessDetails(row.owningPid, out var processName, out var executablePath);
                var remoteHostName = ResolveRemoteHostName(remoteEndPoint.Address);

                connections.Add(new TcpConnectionInfo
                {
                    ProcessId = row.owningPid,
                    ProcessName = processName,
                    ExecutablePath = executablePath,
                    LocalEndPoint = localEndPoint,
                    RemoteEndPoint = remoteEndPoint,
                    RemoteHostName = remoteHostName,
                    State = ((MibTcpState)row.state).ToString().Replace("_", " ")
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }

        return connections;
    }

    private static List<TcpConnectionInfo> GetIpv6TcpConnections()
    {
        var connections = new List<TcpConnectionInfo>();
        int bufferSize = 0;

        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, (int)AddressFamily.InterNetworkV6,
            TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true,
                (int)AddressFamily.InterNetworkV6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

            if (result != 0)
            {
                throw new Win32Exception((int)result, "Failed to get IPv6 TCP table.");
            }

            var table = Marshal.PtrToStructure<MIB_TCP6TABLE_OWNER_PID>(tcpTablePtr);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
            IntPtr rowPtr = tcpTablePtr + Marshal.SizeOf<uint>();

            for (int i = 0; i < table.dwNumEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);

                var localAddress = new IPAddress(row.localAddr, row.localScopeId);
                var remoteAddress = new IPAddress(row.remoteAddr, row.remoteScopeId);
                var localEndPoint = new IPEndPoint(localAddress, ConvertNetworkPort(row.localPort));
                var remoteEndPoint = new IPEndPoint(remoteAddress, ConvertNetworkPort(row.remotePort));

                GetProcessDetails(row.owningPid, out var processName, out var executablePath);
                var remoteHostName = ResolveRemoteHostName(remoteEndPoint.Address);

                connections.Add(new TcpConnectionInfo
                {
                    ProcessId = row.owningPid,
                    ProcessName = processName,
                    ExecutablePath = executablePath,
                    LocalEndPoint = localEndPoint,
                    RemoteEndPoint = remoteEndPoint,
                    RemoteHostName = remoteHostName,
                    State = ((MibTcpState)row.state).ToString().Replace("_", " ")
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }

        return connections;
    }

    private static int ConvertNetworkPort(uint networkPort)
    {
        return (ushort)IPAddress.NetworkToHostOrder((short)(networkPort >> 16));
    }

    private static void GetProcessDetails(int processId, out string processName, out string executablePath)
    {
        processName = "Unknown";
        executablePath = string.Empty;

        try
        {
            var process = Process.GetProcessById(processId);
            processName = process.ProcessName;

            try
            {
                executablePath = process.MainModule?.FileName ?? string.Empty;
            }
            catch (Win32Exception)
            {
                // Access denied for some system processes
            }
            catch (InvalidOperationException)
            {
                // Process has exited or module enumeration not available
            }
        }
        catch
        {
            processName = $"PID:{processId}";
        }
    }

    private static string ResolveRemoteHostName(IPAddress remoteAddress)
    {
        if (remoteAddress.Equals(IPAddress.Any) || remoteAddress.Equals(IPAddress.IPv6Any))
        {
            return string.Empty;
        }

        if (DnsCache.TryGetValue(remoteAddress, out var cachedHostName))
        {
            return cachedHostName;
        }

        string hostName = string.Empty;

        try
        {
            var lookupTask = Dns.GetHostEntryAsync(remoteAddress);
            if (lookupTask.Wait(DnsLookupTimeout))
            {
                hostName = lookupTask.Result.HostName;
            }
        }
        catch (SocketException)
        {
            hostName = string.Empty;
        }
        catch (TaskCanceledException)
        {
            hostName = string.Empty;
        }
        catch (AggregateException ex) when (ex.InnerException is SocketException or TaskCanceledException)
        {
            hostName = string.Empty;
        }
        DnsCache[remoteAddress] = hostName;
        return hostName;
    }
}
