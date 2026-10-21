using Microsoft.UI;
using Microsoft.UI.Xaml.Media;

namespace Snitch.ViewModels;

public class ConnectionViewModel
{
    private static readonly SolidColorBrush GreenBrush = new(Colors.Green);
    private static readonly SolidColorBrush BlueBrush = new(Colors.DodgerBlue);
    private static readonly SolidColorBrush OrangeBrush = new(Colors.Orange);
    private static readonly SolidColorBrush OrangeRedBrush = new(Colors.OrangeRed);
    private static readonly SolidColorBrush YellowBrush = new(Colors.Yellow);
    private static readonly SolidColorBrush RedBrush = new(Colors.Red);
    private static readonly SolidColorBrush GrayBrush = new(Colors.Gray);

    public string ProcessName { get; }
    public int ProcessId { get; }
    public string ExecutablePath { get; }
    public string LocalEndPoint { get; }
    public string RemoteEndPoint { get; }
    public string RemoteHostName { get; }
    public string State { get; }
    public long BytesSent { get; }
    public long BytesReceived { get; }
    public string BytesSentText { get; }
    public string BytesReceivedText { get; }
    public SolidColorBrush StateBrush { get; }

    public ConnectionViewModel(TcpConnectionInfo connection)
    {
        ProcessName = connection.ProcessName;
        ProcessId = connection.ProcessId;
        ExecutablePath = connection.ExecutablePath;
        LocalEndPoint = connection.LocalEndPoint.ToString();
        RemoteEndPoint = connection.RemoteEndPoint.ToString();
        RemoteHostName = string.IsNullOrEmpty(connection.RemoteHostName) 
            ? "" 
            : connection.RemoteHostName;
        State = connection.State;
        BytesSent = connection.BytesSent;
        BytesReceived = connection.BytesReceived;
        BytesSentText = FormatBytes(connection.BytesSent);
        BytesReceivedText = FormatBytes(connection.BytesReceived);
        StateBrush = GetStateBrush(connection.State);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 0)
        {
            return "0 B";
        }

        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double value = bytes;
        int unitIndex = 0;

        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return unitIndex == 0
            ? $"{(long)value} {units[unitIndex]}"
            : $"{value:0.##} {units[unitIndex]}";
    }

    private static SolidColorBrush GetStateBrush(string state)
    {
        return state switch
        {
            "ESTAB" => GreenBrush,
            "LISTEN" => BlueBrush,
            "TIME WAIT" => OrangeBrush,
            "CLOSE WAIT" => OrangeRedBrush,
            "SYN SENT" => YellowBrush,
            "SYN RCVD" => YellowBrush,
            "FIN WAIT1" => OrangeBrush,
            "FIN WAIT2" => OrangeBrush,
            "CLOSING" => RedBrush,
            "LAST ACK" => RedBrush,
            "CLOSED" => GrayBrush,
            _ => GrayBrush
        };
    }
}
