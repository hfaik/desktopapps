using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;

namespace IpHelper;

public partial class MainWindow : Window
{
    enum Mode { Passive, Verify, Full }

    readonly System.Collections.ObjectModel.ObservableCollection<NetInfo> nets = new();
    static readonly string NetFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "IpHelper", "networks.json");
    readonly Dictionary<uint, HostEntry> hosts = new();
    readonly System.Collections.ObjectModel.ObservableCollection<HostEntry> used = new();
    readonly DispatcherTimer timer = new();
    CancellationTokenSource? cts;
    bool busy;
    int sessionProbes;

    public MainWindow()
    {
        InitializeComponent();
        usedGrid.ItemsSource = used;
        timer.Tick += async (_, _) => { if (!busy) await RunAsync(Mode.Verify); };
    }

    void Window_Loaded(object sender, RoutedEventArgs e)
    {
        foreach (var n in NetInfo.Discover()) nets.Add(n);
        netList.ItemsSource = nets;
        int found = nets.Count;
        try
        {
            if (File.Exists(NetFile))
                foreach (var cidr in System.Text.Json.JsonSerializer.Deserialize<List<string>>(File.ReadAllText(NetFile)) ?? new())
                    if (NetInfo.TryCreateCustom(cidr, nets, out _) is { } c) nets.Add(c);
        }
        catch (Exception ex) { Log("Kayıtlı ağlar okunamadı: " + ex.Message); }
        Log($"{found} ağ otomatik bulundu (işaretsiz), {nets.Count - found} kayıtlı özel ağ yüklendi.");
        status.Text = "Taranacak ağları sen belirle: listeden işaretle ya da aşağıdan kendi ağını ekle.";
    }

    void SaveCustomNets()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(NetFile)!);
            File.WriteAllText(NetFile, System.Text.Json.JsonSerializer.Serialize(nets.Where(n => n.Custom).Select(n => n.Cidr).ToList()));
        }
        catch (Exception ex) { Log("Ağlar kaydedilemedi: " + ex.Message); }
    }

    void AddNet_Click(object sender, RoutedEventArgs e)
    {
        var net = NetInfo.TryCreateCustom(txtCidr.Text, nets, out string err);
        if (net == null) { status.Text = err; return; }
        nets.Add(net);
        txtCidr.Clear();
        SaveCustomNets();
        Log($"Ağ eklendi: {net.Label}");
        status.Text = "Ağ eklendi.";
    }

    void RemoveNet_Click(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).Tag is not NetInfo net || busy) return;
        nets.Remove(net);
        SaveCustomNets();
        Log($"Ağ silindi: {net.Cidr}");
    }

    void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e) => cts?.Cancel();

    void Log(string msg) => logBox.AppendText($"{DateTime.Now:HH:mm:ss}  {msg}{Environment.NewLine}");

    void SetBusy(bool on)
    {
        busy = on;
        btnPassive.IsEnabled = btnVerify.IsEnabled = btnFull.IsEnabled = btnPorts.IsEnabled = !on;
        btnStop.IsEnabled = on;
    }

    void UpdateStatus(string prefix)
    {
        status.Text = $"{prefix}  |  Oturumda gönderilen ARP isteği: {sessionProbes} (yaklaşık {sessionProbes * Scanner.BytesPerProbe / 1024.0:F1} KB)  |  " +
                      $"Kullanılan: {used.Count(h => h.Status == "Aktif")}";
    }

    async void Passive_Click(object s, RoutedEventArgs e) => await RunAsync(Mode.Passive);
    async void Verify_Click(object s, RoutedEventArgs e) => await RunAsync(Mode.Verify);
    async void Full_Click(object s, RoutedEventArgs e) => await RunAsync(Mode.Full);
    void Stop_Click(object s, RoutedEventArgs e) => cts?.Cancel();

    async Task RunAsync(Mode mode)
    {
        if (busy) return;
        var selected = nets.Where(n => n.Selected && n.Supported).ToList();
        if (selected.Count == 0) { status.Text = "İşaretli taranabilir ağ yok."; return; }

        SetBusy(true);
        cts = new CancellationTokenSource();
        var ct = cts.Token;
        var added = new List<HostEntry>();
        try
        {
            UpdateStatus("ARP önbelleği okunuyor...");
            var cache = await Scanner.ReadArpCacheAsync();

            foreach (var net in selected)
            {
                ct.ThrowIfCancellationRequested();
                var found = cache.Where(kv => net.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value);

                IEnumerable<uint>? targets = mode switch
                {
                    Mode.Full => net.HostRange().Where(ip => ip != net.LocalIp && !found.ContainsKey(ip)),
                    Mode.Verify => hosts.Keys.Where(ip => net.Contains(ip) && ip != net.LocalIp).ToList(),
                    _ => null,
                };

                if (targets != null)
                {
                    UpdateStatus($"{net.Cidr} taranıyor...");
                    Action onProbe = () =>
                    {
                        int n = Interlocked.Increment(ref sessionProbes);
                        if (n % 10 == 0) Dispatcher.BeginInvoke(() => UpdateStatus($"{net.Cidr} taranıyor..."));
                    };
                    var probed = net.UseIcmp
                        ? await Scanner.ProbeIcmpAsync(targets, onProbe, ct)
                        : await Scanner.ProbeAsync(net, targets, onProbe, ct);
                    foreach (var kv in probed) found[kv.Key] = kv.Value;
                    if (mode == Mode.Full) net.LastFullSweep = DateTime.Now;
                }

                if (net.LocalIp != 0) found[net.LocalIp] = net.LocalMac;
                Apply(net, found, mode != Mode.Passive, added);
            }

            RefreshFree();
            UpdateStatus($"Bitti ({mode}).");
        }
        catch (OperationCanceledException)
        {
            UpdateStatus("Durduruldu.");
        }
        catch (Exception ex)
        {
            Log("Hata: " + ex.Message);
            UpdateStatus("Hata oluştu.");
        }
        finally
        {
            SetBusy(false);
        }

        if (chkDns.IsChecked == true && added.Count > 0) await ResolveNamesAsync(added);
    }

    void Apply(NetInfo net, Dictionary<uint, string> found, bool markMissing, List<HostEntry> added)
    {
        foreach (var (ip, mac) in found)
        {
            if (hosts.TryGetValue(ip, out var h))
            {
                if (h.Status != "Aktif") Log($"Geri geldi: {h.Ip}");
                h.Status = "Aktif";
                h.LastSeen = DateTime.Now;
                h.Mac = mac;
            }
            else
            {
                h = new HostEntry
                {
                    IpValue = ip,
                    Network = net.Cidr,
                    Mac = mac,
                    Vendor = Oui.Lookup(mac),
                    Hostname = ip == net.LocalIp ? Environment.MachineName + " (bu bilgisayar)" : "",
                };
                hosts[ip] = h;
                used.Add(h);
                if (ip != net.LocalIp) added.Add(h);
                Log($"Yeni cihaz: {h.Ip}  {mac}  {h.Vendor}");
            }
        }

        if (!markMissing) return;
        foreach (var h in hosts.Values.Where(x => net.Contains(x.IpValue) && !found.ContainsKey(x.IpValue)))
        {
            if (h.Status == "Aktif") Log($"Yanıt yok: {h.Ip}");
            h.Status = "Yanıt yok";
        }
    }

    // Tek tek, sırayla: DNS trafiğini en aza indirmek için paralel sorgu yok.
    async Task ResolveNamesAsync(List<HostEntry> list)
    {
        foreach (var h in list)
        {
            if (!string.IsNullOrEmpty(h.Hostname)) continue;
            h.Hostname = await Scanner.ResolveNameAsync(h.IpValue);
        }
    }

    void RefreshFree()
    {
        var free = new List<FreeEntry>();
        foreach (var net in nets.Where(n => n.LastFullSweep != null))
            foreach (var ip in net.HostRange())
                if (ip != net.LocalIp && !hosts.ContainsKey(ip))
                    free.Add(new FreeEntry { IpValue = ip, Network = net.Cidr });
        freeGrid.ItemsSource = free;
        tabFree.Header = $"Müsait ({free.Count})";
        tabUsed.Header = $"Kullanılan ({used.Count})";
    }

    async void Ports_Click(object s, RoutedEventArgs e)
    {
        if (usedGrid.SelectedItem is not HostEntry h) { status.Text = "Önce Kullanılan listesinden bir cihaz seç."; return; }
        SetBusy(true);
        cts = new CancellationTokenSource();
        try
        {
            h.OpenPorts = "taranıyor...";
            status.Text = $"{h.Ip} portları taranıyor...";
            h.OpenPorts = await Scanner.ScanPortsAsync(h.IpValue, cts.Token);
            Log($"Port taraması {h.Ip}: {h.OpenPorts}");
            status.Text = "Port taraması bitti.";
        }
        catch (OperationCanceledException) { h.OpenPorts = ""; status.Text = "Durduruldu."; }
        finally { SetBusy(false); }
    }

    void Periodic_Changed(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(txtMinutes.Text, out int min) || min < 1) { min = 15; txtMinutes.Text = "15"; }
        timer.Interval = TimeSpan.FromMinutes(min);
        timer.IsEnabled = chkPeriodic.IsChecked == true;
        if (timer.IsEnabled) Log($"Periyodik doğrulama açık: {min} dk");
    }

    void Csv_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = $"ip-listesi-{DateTime.Now:yyyyMMdd-HHmm}.csv" };
        if (dlg.ShowDialog() != true) return;

        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder("Durum;IP;Ağ;MAC;Üretici;Hostname;Açık Portlar;Son Görülme\r\n");
        foreach (var h in used.OrderBy(x => x.IpValue))
            sb.Append(string.Join(';', Q(h.Status), Q(h.Ip), Q(h.Network), Q(h.Mac), Q(h.Vendor), Q(h.Hostname), Q(h.OpenPorts), Q(h.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")))).Append("\r\n");
        if (freeGrid.ItemsSource is IEnumerable<FreeEntry> free)
            foreach (var f in free)
                sb.Append(string.Join(';', Q("Müsait"), Q(f.Ip), Q(f.Network), Q(""), Q(""), Q(""), Q(""), Q(""))).Append("\r\n");

        File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
        status.Text = "Kaydedildi: " + dlg.FileName;
    }
}
