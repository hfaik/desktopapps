using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace IpHelper;

public static class IpUtil
{
    public static uint ToUInt(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static string ToStr(uint v) => $"{v >> 24}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}";

    public static uint ToNative(uint v) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(v);

    public static bool TryParse(string s, out uint v)
    {
        v = 0;
        if (!IPAddress.TryParse(s, out var a) || a.AddressFamily != AddressFamily.InterNetwork) return false;
        v = ToUInt(a);
        return true;
    }
}

public class ObservableBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

public class HostEntry : ObservableBase
{
    string _mac = "", _vendor = "", _host = "", _ports = "", _status = "Aktif";
    DateTime _lastSeen = DateTime.Now;

    public uint IpValue { get; init; }
    public string Ip => IpUtil.ToStr(IpValue);
    public string Network { get; init; } = "";
    public string Mac { get => _mac; set => Set(ref _mac, value); }
    public string Vendor { get => _vendor; set => Set(ref _vendor, value); }
    public string Hostname { get => _host; set => Set(ref _host, value); }
    public string OpenPorts { get => _ports; set => Set(ref _ports, value); }
    public string Status { get => _status; set => Set(ref _status, value); }
    public DateTime LastSeen { get => _lastSeen; set => Set(ref _lastSeen, value); }
}

public class FreeEntry
{
    public uint IpValue { get; init; }
    public string Ip => IpUtil.ToStr(IpValue);
    public string Network { get; init; } = "";
}

public class NetInfo
{
    public const long MaxHosts = 1022; // /22'ye kadar

    public string Name { get; init; } = "";
    public uint LocalIp { get; init; }
    public string LocalMac { get; init; } = "";
    public int Prefix { get; init; }
    public uint Network { get; init; }
    public uint Broadcast { get; init; }
    public bool ArpCapable { get; init; }
    public bool Selected { get; set; }
    public DateTime? LastFullSweep { get; set; }

    public long HostCount => (1L << (32 - Prefix)) - 2;
    public bool Supported => ArpCapable && HostCount <= MaxHosts;
    public string Cidr => $"{IpUtil.ToStr(Network)}/{Prefix}";

    public string Label
    {
        get
        {
            var s = $"{Cidr}  ({Name}, {HostCount} adres)";
            if (!ArpCapable) return s + " - ARP desteklenmiyor, atlanır";
            if (HostCount > MaxHosts) return s + " - çok büyük, atlanır";
            return s;
        }
    }

    public bool Contains(uint ip) => ip > Network && ip < Broadcast;

    public IEnumerable<uint> HostRange()
    {
        for (uint ip = Network + 1; ip < Broadcast; ip++) yield return ip;
    }

    public static List<NetInfo> Discover()
    {
        var list = new List<NetInfo>();
        var seen = new HashSet<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            bool arp = nic.NetworkInterfaceType is NetworkInterfaceType.Ethernet
                or NetworkInterfaceType.Wireless80211
                or NetworkInterfaceType.GigabitEthernet
                or NetworkInterfaceType.FastEthernetT
                or NetworkInterfaceType.FastEthernetFx;

            var mac = string.Join(":", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));

            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                int prefix = ua.PrefixLength;
                if (prefix is >= 31 or <= 0) continue;
                uint ip = IpUtil.ToUInt(ua.Address);
                if ((ip >> 24) == 127 || (ip >> 16) == 0xA9FE) continue; // loopback, APIPA
                uint mask = uint.MaxValue << (32 - prefix);
                uint net = ip & mask;
                var n = new NetInfo
                {
                    Name = nic.Name,
                    LocalIp = ip,
                    LocalMac = mac,
                    Prefix = prefix,
                    Network = net,
                    Broadcast = net | ~mask,
                    ArpCapable = arp,
                };
                if (!seen.Add(n.Cidr)) continue;
                n.Selected = n.Supported;
                list.Add(n);
            }
        }
        return list;
    }
}
