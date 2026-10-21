using System.Collections.Generic;

namespace Snitch;

public static partial class NetworkHelper
{
    private const uint ErrorInsufficientBuffer = 122;

    public static List<TcpConnectionInfo> GetAllTcpConnections()
    {
        return GetAllTcpConnections(includeConnectionStats: false);
    }

    public static List<TcpConnectionInfo> GetAllTcpConnections(bool includeConnectionStats)
    {
        var connections = new List<TcpConnectionInfo>();
        connections.AddRange(GetIpv4TcpConnections(includeConnectionStats));
        connections.AddRange(GetIpv6TcpConnections(includeConnectionStats));

        return connections;
    }
}
