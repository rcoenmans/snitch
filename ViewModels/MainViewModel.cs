using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Snitch.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private readonly Dictionary<string, (long BytesSent, long BytesReceived)> _lastConnectionTotals = new();
    private CancellationTokenSource? _autoRefreshCts;
    private Task? _autoRefreshTask;

    [ObservableProperty]
    private ObservableCollection<ConnectionViewModel> connections = new();

    [ObservableProperty]
    private bool isLoading;

    [ObservableProperty]
    private int totalConnections;

    [ObservableProperty]
    private string statusMessage = "Ready";

    [ObservableProperty]
    private bool hideLocalConnections;

    public MainViewModel()
    {
        StartAutoRefresh();
    }

    partial void OnHideLocalConnectionsChanged(bool value)
    {
        // Reload connections when filter changes
        _ = LoadConnectionsAsync();
    }

    private void StartAutoRefresh()
    {
        _autoRefreshCts = new CancellationTokenSource();
        _autoRefreshTask = AutoRefreshLoopAsync(_autoRefreshCts.Token);
    }

    private void StopAutoRefresh()
    {
        var cts = _autoRefreshCts;
        _autoRefreshCts = null;

        if (cts is null)
        {
            return;
        }

        cts.Cancel();
        cts.Dispose();
    }

    private async Task AutoRefreshLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await LoadConnectionsAsync();
                await Task.Delay(5000, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
                try
                {
                    await Task.Delay(5000, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    public async Task LoadConnectionsAsync()
    {
        await _refreshLock.WaitAsync();

        try
        {
            IsLoading = true;
            StatusMessage = "Loading connections...";

            // Perform data retrieval on background thread
            var connectionList = await Task.Run(() =>
            {
                return NetworkHelper.GetAllTcpConnections(includeConnectionStats: true);
            });

            // Apply filter if enabled
            if (HideLocalConnections)
            {
                connectionList = connectionList
                    .Where(c => !IsLocalConnection(c))
                    .ToList();
            }

            foreach (var connection in connectionList)
            {
                var key = GetConnectionKey(connection);
                var lifetimeSent = connection.BytesSent;
                var lifetimeReceived = connection.BytesReceived;

                connection.LifetimeBytesSent = lifetimeSent;
                connection.LifetimeBytesReceived = lifetimeReceived;

                if (_lastConnectionTotals.TryGetValue(key, out var previous))
                {
                    connection.BytesSent = Math.Max(0, lifetimeSent - previous.BytesSent);
                    connection.BytesReceived = Math.Max(0, lifetimeReceived - previous.BytesReceived);
                }
                else
                {
                    connection.BytesSent = 0;
                    connection.BytesReceived = 0;
                }

                _lastConnectionTotals[key] = (lifetimeSent, lifetimeReceived);
            }

            var staleKeys = _lastConnectionTotals.Keys
                .Except(connectionList.Select(GetConnectionKey))
                .ToList();

            foreach (var staleKey in staleKeys)
            {
                _lastConnectionTotals.Remove(staleKey);
            }

            // Create ViewModels on UI thread (required for WinUI SolidColorBrush creation)
            var viewModels = connectionList
                .Select(c => new ConnectionViewModel(c))
                .OrderBy(c => c.ProcessName)
                .ThenBy(c => c.State)
                .ToList();

            Connections.Clear();
            foreach (var vm in viewModels)
            {
                Connections.Add(vm);
            }

            TotalConnections = connectionList.Count;
            StatusMessage = $"Last updated: {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
            _refreshLock.Release();
        }
    }

    private static string GetConnectionKey(TcpConnectionInfo connection)
    {
        return $"{connection.ProcessId}:{connection.LocalEndPoint}:{connection.RemoteEndPoint}";
    }

    private static bool IsLocalConnection(TcpConnectionInfo connection)
    {
        var remoteIp = connection.RemoteEndPoint.Address.ToString();

        // Filter out 127.0.0.1 (localhost), 0.0.0.0 (unspecified), and ::1 (IPv6 localhost)
        return remoteIp == "127.0.0.1" || 
               remoteIp == "0.0.0.0" || 
               remoteIp == "::1" ||
               remoteIp.StartsWith("127.") ||
               connection.LocalEndPoint.Address.ToString() == connection.RemoteEndPoint.Address.ToString();
    }

    public void Dispose()
    {
        StopAutoRefresh();
        _autoRefreshTask?.Wait(TimeSpan.FromSeconds(2));
        _autoRefreshTask = null;
        _refreshLock.Dispose();
    }
}
