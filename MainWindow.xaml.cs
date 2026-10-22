using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Snitch.ViewModels;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Snitch
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        public MainViewModel ViewModel { get; }

        public bool IsDarkMode => ((FrameworkElement)Content).RequestedTheme == ElementTheme.Dark;

        public MainWindow()
        {
            InitializeComponent();
            ViewModel = new MainViewModel();
            Closed += OnClosed;
            _ = ViewModel.LoadConnectionsAsync();
        }

        private void OnThemeToggleClick(object sender, RoutedEventArgs e)
        {
            var root = (FrameworkElement)Content;
            root.RequestedTheme = root.RequestedTheme == ElementTheme.Dark
                ? ElementTheme.Light
                : ElementTheme.Dark;

            // Update icon: moon for dark mode, sun for light mode
            ThemeIcon.Glyph = root.RequestedTheme == ElementTheme.Dark ? "\uE708" : "\uE706";
        }

        private void OnColumnResize(object sender, DragDeltaEventArgs e)
        {
            if (sender is not Thumb thumb || thumb.Parent is not Grid grid)
            {
                return;
            }

            if (thumb.Tag is not string tag || !int.TryParse(tag, out var columnIndex))
            {
                return;
            }

            if (columnIndex < 0 || columnIndex >= grid.ColumnDefinitions.Count - 1)
            {
                return;
            }

            var leftColumn = grid.ColumnDefinitions[columnIndex];
            var rightColumn = grid.ColumnDefinitions[columnIndex + 1];

            if (!leftColumn.Width.IsAbsolute || !rightColumn.Width.IsAbsolute)
            {
                return;
            }

            var newLeftWidth = Math.Max(leftColumn.MinWidth, leftColumn.Width.Value + e.HorizontalChange);
            var newRightWidth = Math.Max(rightColumn.MinWidth, rightColumn.Width.Value - e.HorizontalChange);

            leftColumn.Width = new GridLength(newLeftWidth);
            rightColumn.Width = new GridLength(newRightWidth);
        }

        private void OnClosed(object sender, WindowEventArgs args)
        {
            Closed -= OnClosed;
            ViewModel.Dispose();
        }
    }
}
