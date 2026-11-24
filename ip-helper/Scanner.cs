using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace IpHelper;

/// <summary>
/// Düşük trafikli tespit: önce işletim sisteminin ARP önbelleği okunur (0 paket),
/// sonra yalnızca gerekli adreslere tek bir ARP isteği gönderilir (~60 bayt/istek).
/// ICMP süpürmesi, port taraması veya toplu DNS sorgusu yapılmaz.
/// </summary>
public static class Scanner
{
    // ARP paketi: 14 bayt Ethernet + 28 bayt ARP, en az 60 bayt çerçeve; istek + yanıt için ~120 bayt.
    public const int BytesPerProbe = 120;

    const int MaxParallel = 16;      // aynı anda bekleyen en fazla istek
    const int SpacingMs = 20;        // istekler arası en az bekleme (~50 istek/sn üst sınır)

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern int SendARP(uint destIp, uint srcIp, byte[] mac, ref int len);

    static readonly Regex ArpLine = new(
        @"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
        RegexOptions.Compiled);

    public static string FormatMac(IEnumerable<byte> b) => string.Join(":", b.Select(x => x.ToString("X2")));

    /// <summary>İşletim sisteminin ARP tablosunu okur. Ağa hiçbir paket göndermez.</summary>
    public static Task<Dictionary<uint, string>> ReadArpCacheAsync() => Task.Run(() =>
    {
        var result = new Dictionary<uint, string>();
        var psi = new ProcessStartInfo("arp", "-a")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        if (p == null) return result;
        string text = p.StandardOutput.ReadToEnd();
        p.WaitForExit();

        foreach (var line in text.Split('\n'))
        {
            var m = ArpLine.Match(line);
            if (!m.Success) continue;
            string mac = m.Groups[2].Value.ToUpperInvariant();
            if (mac.StartsWith("FF-FF-FF") || mac.StartsWith("01-00-5E") || mac.StartsWith("33-33")) continue;
            if (!IpUtil.TryParse(m.Groups[1].Value, out uint ip)) continue;
            result[ip] = mac.Replace('-', ':');
        }
        return result;
    });

    /// <summary>Verilen adreslere hız sınırlı, tekil ARP isteği gönderir.</summary>
    public static async Task<Dictionary<uint, string>> ProbeAsync(
        NetInfo net, IEnumerable<uint> targets, Action onProbe, CancellationToken ct)
    {
        var found = new ConcurrentDictionary<uint, string>();
        using var gate = new SemaphoreSlim(MaxParallel);
        var tasks = new List<Task>();
        try
        {
            foreach (uint target in targets)
            {
                await gate.WaitAsync(ct);
                await Task.Delay(SpacingMs, ct);
                tasks.Add(Task.Run(() =>
                {
                    try
                    {
                        var mac = new byte[6];
                        int len = 6;
                        int r = SendARP(IpUtil.ToNative(target), IpUtil.ToNative(net.LocalIp), mac, ref len);
                        onProbe();
                        if (r == 0 && len == 6 && mac.Any(b => b != 0)) found[target] = FormatMac(mac);
                    }
                    finally { gate.Release(); }
                }, CancellationToken.None));
            }
        }
        finally
        {
            await Task.WhenAll(tasks);
        }
        return new Dictionary<uint, string>(found);
    }

    public static async Task<string> ResolveNameAsync(uint ip)
    {
        try
        {
            var e = await Dns.GetHostEntryAsync(IpUtil.ToStr(ip)).WaitAsync(TimeSpan.FromSeconds(2));
            return e.HostName;
        }
        catch { return ""; }
    }

    public static readonly (int Port, string Name)[] CommonPorts =
    {
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (53, "dns"), (80, "http"), (135, "rpc"),
        (139, "netbios"), (443, "https"), (445, "smb"), (3389, "rdp"), (8080, "http-alt"),
    };

    /// <summary>Tek bir cihazda yaygın portları dener. Yalnızca kullanıcı isteğiyle çağrılır.</summary>
    public static async Task<string> ScanPortsAsync(uint ip, CancellationToken ct)
    {
        var open = new ConcurrentBag<(int, string)>();
        using var gate = new SemaphoreSlim(4);
        var tasks = CommonPorts.Select(async p =>
        {
            await gate.WaitAsync(ct);
            try
            {
                using var c = new TcpClient();
                using var t = CancellationTokenSource.CreateLinkedTokenSource(ct);
                t.CancelAfter(700);
                await c.ConnectAsync(new IPAddress(BitConverter.GetBytes(IpUtil.ToNative(ip))), p.Port, t.Token);
                open.Add(p);
            }
            catch { }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks);
        var list = open.OrderBy(o => o.Item1).Select(o => $"{o.Item1}/{o.Item2}").ToList();
        return list.Count == 0 ? "açık yok" : string.Join(", ", list);
    }
}

/// <summary>Çevrimdışı çalışan kısa MAC üretici tablosu (ağ sorgusu yapmaz).</summary>
public static class Oui
{
    static readonly Dictionary<string, string> Table = new()
    {
        ["005056"] = "VMware", ["000C29"] = "VMware", ["000569"] = "VMware",
        ["080027"] = "VirtualBox", ["00155D"] = "Microsoft Hyper-V", ["525400"] = "QEMU/KVM",
        ["B827EB"] = "Raspberry Pi", ["DCA632"] = "Raspberry Pi", ["E45F01"] = "Raspberry Pi", ["28CDC1"] = "Raspberry Pi",
        ["3C5AB4"] = "Google", ["F4F5D8"] = "Google",
        ["000393"] = "Apple", ["0017F2"] = "Apple", ["3C0754"] = "Apple", ["F01898"] = "Apple",
        ["50C7BF"] = "TP-Link", ["14CC20"] = "TP-Link", ["F4F26D"] = "TP-Link",
        ["000C42"] = "MikroTik", ["4C5E0C"] = "MikroTik", ["E48D8C"] = "MikroTik",
        ["001B21"] = "Intel", ["3C970E"] = "Intel", ["001CC0"] = "Intel",
        ["24A43C"] = "Ubiquiti", ["44D9E7"] = "Ubiquiti", ["FCECDA"] = "Ubiquiti",
        ["00000C"] = "Cisco", ["001B54"] = "Cisco",
        ["001EC9"] = "Dell", ["180373"] = "Dell", ["B8AC6F"] = "Dell",
        ["3CD92B"] = "HP", ["00215A"] = "HP",
        ["000FB5"] = "Netgear", ["0014BF"] = "Linksys", ["00E04C"] = "Realtek",
    };

    public static string Lookup(string mac)
    {
        var hex = mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
        if (hex.Length < 6) return "";
        if (Table.TryGetValue(hex[..6], out var v)) return v;
        // Yerel yönetilen bit: telefonların rastgele MAC adresi gibi
        if ((Convert.ToByte(hex[..2], 16) & 0x02) != 0) return "Rastgele/özel MAC";
        return "";
    }
}
