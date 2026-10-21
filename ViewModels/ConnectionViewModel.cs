using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI;
using Microsoft.UI.Xaml.Media;

namespace Snitch.ViewModels;

public class ConnectionViewModel : ObservableObject
{
    private static readonly SolidColorBrush GreenBrush = new(Colors.Green);
    private static readonly SolidColorBrush BlueBrush = new(Colors.DodgerBlue);
    private static readonly SolidColorBrush OrangeBrush = new(Colors.Orange);
    private static readonly SolidColorBrush OrangeRedBrush = new(Colors.OrangeRed);
    private static readonly SolidColorBrush YellowBrush = new(Colors.Yellow);
    private static readonly SolidColorBrush RedBrush = new(Colors.Red);
    private static readonly SolidColorBrush GrayBrush = new(Colors.Gray);

    private string _processName = string.Empty;
    private int _processId;
    private string _executablePath = string.Empty;
    private string _localEndPoint = string.Empty;
    private string _remoteEndPoint = string.Empty;
    private string _remoteHostName = string.Empty;
    private string _state = string.Empty;
    private SolidColorBrush _stateBrush = GrayBrush;

    public string Key { get; }

    public string ProcessName
    {
        get => _processName;
        private set => SetProperty(ref _processName, value);
    }

    public int ProcessId
    {
        get => _processId;
        private set => SetProperty(ref _processId, value);
    }

    public string ExecutablePath
    {
        get => _executablePath;
        private set => SetProperty(ref _executablePath, value);
    }

    public string LocalEndPoint
    {
        get => _localEndPoint;
        private set => SetProperty(ref _localEndPoint, value);
    }

    public string RemoteEndPoint
    {
        get => _remoteEndPoint;
        private set => SetProperty(ref _remoteEndPoint, value);
    }

    public string RemoteHostName
    {
        get => _remoteHostName;
        private set => SetProperty(ref _remoteHostName, value);
    }

    public string State
    {
        get => _state;
        private set => SetProperty(ref _state, value);
    }

    public SolidColorBrush StateBrush
    {
        get => _stateBrush;
        private set => SetProperty(ref _stateBrush, value);
    }

    public ConnectionViewModel(TcpConnectionInfo connection)
    {
        Key = BuildKey(connection);
        Update(connection);
    }

    public static string BuildKey(TcpConnectionInfo connection)
    {
        return $"{connection.ProcessId}|{connection.LocalEndPoint}|{connection.RemoteEndPoint}";
    }

    public bool NeedsUpdate(TcpConnectionInfo connection)
    {
        return ProcessName != connection.ProcessName
            || ProcessId != connection.ProcessId
            || ExecutablePath != connection.ExecutablePath
            || LocalEndPoint != connection.LocalEndPoint.ToString()
            || RemoteEndPoint != connection.RemoteEndPoint.ToString()
            || RemoteHostName != connection.RemoteHostName
            || State != connection.State;
    }

    public void Update(TcpConnectionInfo connection)
    {
        ProcessName = connection.ProcessName;
        ProcessId = connection.ProcessId;
        ExecutablePath = connection.ExecutablePath;
        LocalEndPoint = connection.LocalEndPoint.ToString();
        RemoteEndPoint = connection.RemoteEndPoint.ToString();
        RemoteHostName = string.IsNullOrEmpty(connection.RemoteHostName)
            ? string.Empty
            : connection.RemoteHostName;
        State = connection.State;
        StateBrush = GetStateBrush(connection.State);
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
