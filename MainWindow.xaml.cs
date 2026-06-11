using Microsoft.UI.Xaml;
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

        private void OnClosed(object sender, WindowEventArgs args)
        {
            Closed -= OnClosed;
            ViewModel.Dispose();
        }
    }
}
