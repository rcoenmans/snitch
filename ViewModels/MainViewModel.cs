using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Snitch.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private readonly Dictionary<string, ConnectionViewModel> _connectionMap = new(StringComparer.Ordinal);
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
                return NetworkHelper.GetAllTcpConnections();
            });

            // Apply filter if enabled
            if (HideLocalConnections)
            {
                connectionList = connectionList
                    .Where(c => !IsLocalConnection(c))
                    .ToList();
            }

            var sortedConnections = connectionList
                .OrderBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(c => c.State, StringComparer.OrdinalIgnoreCase)
                .ThenBy(c => c.ProcessId)
                .ThenBy(c => c.LocalEndPoint.ToString(), StringComparer.Ordinal)
                .ThenBy(c => c.RemoteEndPoint.ToString(), StringComparer.Ordinal)
                .ToList();

            ApplyConnectionDiff(sortedConnections);

            TotalConnections = sortedConnections.Count;
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

    private void ApplyConnectionDiff(IReadOnlyList<TcpConnectionInfo> sortedConnections)
    {
        var desiredKeys = new HashSet<string>(
            sortedConnections.Select(ConnectionViewModel.BuildKey),
            StringComparer.Ordinal);

        for (int i = Connections.Count - 1; i >= 0; i--)
        {
            var existing = Connections[i];
            if (desiredKeys.Contains(existing.Key))
            {
                continue;
            }

            Connections.RemoveAt(i);
            _connectionMap.Remove(existing.Key);
        }

        for (int targetIndex = 0; targetIndex < sortedConnections.Count; targetIndex++)
        {
            var connection = sortedConnections[targetIndex];
            var key = ConnectionViewModel.BuildKey(connection);

            if (_connectionMap.TryGetValue(key, out var vm))
            {
                if (vm.NeedsUpdate(connection))
                {
                    vm.Update(connection);
                }

                var currentIndex = Connections.IndexOf(vm);
                if (currentIndex >= 0 && currentIndex != targetIndex)
                {
                    var clampedTargetIndex = Math.Clamp(targetIndex, 0, Math.Max(0, Connections.Count - 1));
                    if (currentIndex != clampedTargetIndex)
                    {
                        Connections.Move(currentIndex, clampedTargetIndex);
                    }
                }

                continue;
            }

            var created = new ConnectionViewModel(connection);
            var insertIndex = Math.Clamp(targetIndex, 0, Connections.Count);
            Connections.Insert(insertIndex, created);
            _connectionMap[key] = created;
        }
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
        _connectionMap.Clear();
        _refreshLock.Dispose();
    }
}
