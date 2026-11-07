package com.g120s.janus.discovery;

import com.g120s.janus.model.*;
import com.g120s.janus.l2.*;
import com.g120s.janus.virtualization.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class DiscoveryOrchestrator {
    private final DiscoveryConfig cfg;
    private final ExecutorService pool;
    private final List<Integer> probePorts = List.of(22,23,53,80,135,139,443,445,902,
            3389,5985,5986,8006,8080,8443,9440,16509);

    public DiscoveryOrchestrator(DiscoveryConfig cfg) {
        this.cfg = cfg;
        this.pool = Executors.newFixedThreadPool(Math.max(2, cfg.threadPool));
    }

    public DiscoveryResult run() throws Exception {
        DiscoveryResult r = new DiscoveryResult();
        r.startedAt = System.currentTimeMillis();

        List<Future<List<NeighborRecord>>> sniffFutures = new ArrayList<>();
        if (cfg.lldp) {
            for (String iface : localIfaces()) {
                sniffFutures.add(pool.submit(() -> NeighborSniffer.capture(
                        new NeighborSniffer.CaptureOptions(iface, cfg.lldpDurationMs))));
            }
        }

        // 1) Başlangıç segmentleri
        Deque<NetworkSegment> frontier = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        if (cfg.seedCidrs.isEmpty()) {
            for (String cidr : localCidrs()) frontier.add(new NetworkSegment(cidr));
        } else {
            for (String c : cfg.seedCidrs) frontier.add(new NetworkSegment(c));
        }

        Map<String, Device> byIp = new HashMap<>();

        // 2) BFS
        int generated = 0;
        while (!frontier.isEmpty() && generated < cfg.maxSubnets && visited.size() < cfg.maxDepth * 64) {
            NetworkSegment seg = frontier.poll();
            if (!visited.add(seg.cidr)) continue;
            r.segments.add(seg);
            generated++;

            // 2a) Host keşfi (paralel stratejiler)
            discoverHosts(seg, byIp, r);

            // 2b) Bu segmentteki her aktif cihaz için servis + SNMP
            for (Device d : byIp.values()) {
                if (!sameCidr(d.ip, seg.cidr)) continue;
                enrich(d, byIp, r, frontier, visited);
            }
        }

        r.devices.addAll(byIp.values());

        // 3) Sanallaştırma API'leri (verilen kimlik bilgileriyle)
        for (DiscoveryConfig.Credential c : cfg.vmCreds) {
            try {
                List<VirtualizationHost> found = switch (c.kind) {
                    case "esxi" -> List.of(EsxiDiscovery.discover(newHost(c), c.user, c.passOrKey, r.vms));
                    case "proxmox" -> List.of(ProxmoxDiscovery.discover(
                            c.host, c.port, c.user, c.passOrKey, r.vms));
                    case "kvm" -> List.of(KvmDiscovery.discover(c.host, c.user, c.passOrKey, r.vms));
                    case "hyperv" -> List.of(HyperVDiscovery.discover(
                            new HyperVDiscovery.Options(c.host, c.port, c.useHttps,
                                    c.domain, c.user, c.passOrKey), r.vms));
                    case "vcenter" -> VCenterDiscovery.discover(
                            new VCenterDiscovery.Options(c.host, c.user, c.passOrKey, c.ignoreCert), r.vms);
                    case "libvirt" -> LibvirtDiscovery.discover(
                            new LibvirtDiscovery.Options(c.host, c.user, c.passOrKey), r.vms);
                    default -> List.of();
                };
                for (VirtualizationHost h : found) {
                    r.vhosts.add(h);
                    // Yönetim alt ağlarını BFS'e ekle
                    for (String net : h.managementNets) {
                        if (!net.contains("/")) continue;
                        if (!visited.contains(net)) frontier.add(new NetworkSegment(net));
                    }
                }
            } catch (Exception ex) {
                r.warnings.add(c.kind + "@" + c.host + ": " + ex.getMessage());
            }
        }
        // Eklenen ağları da tara
        while (!frontier.isEmpty()) {
            NetworkSegment seg = frontier.poll();
            if (!visited.add(seg.cidr) || generated++ >= cfg.maxSubnets) continue;
            r.segments.add(seg);
            discoverHosts(seg, byIp, r);
        }
        r.devices.clear();
        r.devices.addAll(byIp.values());

        List<NeighborRecord> neighbors = new ArrayList<>();
        for (Future<List<NeighborRecord>> future : sniffFutures) {
            try {
                neighbors.addAll(future.get());
            } catch (ExecutionException e) {
                r.warnings.add("lldp/cdp: " + e.getCause().getMessage());
            }
        }
        if (!neighbors.isEmpty()) {
            TopologyBuilder.apply(r, neighbors);
            for (Device device : r.devices) {
                if (device.ip == null) continue;
                byIp.putIfAbsent(device.ip.getHostAddress(), device);
                String cidr = toCidr(device.ip.getHostAddress());
                if (cidr != null && !visited.contains(cidr)) {
                    NetworkSegment segment = new NetworkSegment(cidr);
                    segment.discoveredBy.add("lldp-mgmt");
                    frontier.add(segment);
                }
            }
            while (!frontier.isEmpty() && generated < cfg.maxSubnets) {
                NetworkSegment segment = frontier.poll();
                if (!visited.add(segment.cidr)) continue;
                r.segments.add(segment);
                generated++;
                discoverHosts(segment, byIp, r);
            }
            r.devices.clear();
            r.devices.addAll(byIp.values());
        }

        deduplicateVirtualization(r);

        // 4) VM ↔ Host eşleme
        VMHostMatcher.match(r);

        r.finishedAt = System.currentTimeMillis();
        pool.shutdown();
        return r;
    }

    private void discoverHosts(NetworkSegment seg, Map<String, Device> byIp, DiscoveryResult r)
            throws Exception {
        // --- TCP sweep
        if (cfg.tcp) {
            List<InetAddress> ips = expand(seg.cidr, 1024);
            Map<InetAddress, List<Integer>> scans = new LinkedHashMap<>();
            for (InetAddress ip : ips) {
                scans.put(ip, HostScanners.tcpScan(pool, ip, probePorts, cfg.tcpTimeoutMs));
            }
            for (var scan : scans.entrySet()) {
                List<Integer> open = scan.getValue();
                if (!open.isEmpty()) {
                    Device d = byIp.computeIfAbsent(scan.getKey().getHostAddress(), k -> new Device());
                    d.ip = scan.getKey();
                    d.openPorts.addAll(open);
                    d.discoveredBy.add("tcp");
                }
            }
        }
        // --- ICMP
        if (cfg.icmp) {
            for (InetAddress ip : expand(seg.cidr, 1024)) {
                if (HostScanners.icmp(ip, 800)) {
                    Device d = byIp.computeIfAbsent(ip.getHostAddress(), k -> new Device());
                    d.ip = ip; d.discoveredBy.add("icmp");
                }
            }
        }
        // --- Multicast keşif (tek sefer, tüm segment için)
        if (cfg.mdns) {
            try {
                for (InetAddress ia : MulticastScanners.mdns(2000)) {
                    Device d = byIp.computeIfAbsent(ia.getHostAddress(), k -> new Device());
                    d.ip = ia;
                    d.discoveredBy.add("mdns");
                    d.services.add("mdns");
                }
            } catch (Exception e) {
                r.warnings.add("mdns: " + e.getMessage());
            }
        }
        if (cfg.ssdp) {
            try {
                for (InetAddress ia : MulticastScanners.ssdp(2000)) {
                    Device d = byIp.computeIfAbsent(ia.getHostAddress(), k -> new Device());
                    d.ip = ia;
                    d.discoveredBy.add("ssdp");
                    d.services.add("upnp");
                }
            } catch (Exception e) {
                r.warnings.add("ssdp: " + e.getMessage());
            }
        }
        // --- ARP (yerel segment ise)
        if (cfg.arp) {
            try {
                for (String ifName : localIfaces()) {
                    String local = localCidr(ifName);
                    if (local == null || !local.equals(seg.cidr)) continue;
                    for (L2Scanner.ArpEntry e : L2Scanner.arpScan(ifName, seg.cidr, 3000)) {
                        Device d = byIp.computeIfAbsent(e.ip(), k -> new Device());
                        d.ip = InetAddress.getByName(e.ip());
                        d.mac = e.mac();
                        d.discoveredBy.add("arp");
                    }
                }
            } catch (Exception e) {
                r.warnings.add("arp@" + seg.cidr + ": " + e.getMessage());
            }
        }
        // --- NetBIOS (her aktif IP için hızlı)
        if (cfg.netbios) {
            for (Device d : byIp.values()) {
                if (d.ip == null || d.discoveredBy.contains("netbios")) continue;
                if (!sameCidr(d.ip, seg.cidr)) continue;
                MulticastScanners.netbios(d.ip, 250).forEach((ia, name) -> {
                    d.hostname = name;
                    d.discoveredBy.add("netbios");
                });
            }
        }
    }

    /** SNMP ile sistem bilgisi + ek ağlar (route/ARP). */
    private void enrich(Device d, Map<String, Device> byIp, DiscoveryResult r,
                        Deque<NetworkSegment> frontier, Set<String> visited) {
        if (d.ip == null) return;
        if (d.vendor == null) {
            String vendor = VirtualizationDetector.vendorByOuiPrefix(d.mac);
            if (!vendor.isEmpty()) d.vendor = vendor;
        }
        d.kind = d.openPorts.contains(902) || d.openPorts.contains(8006) ||
                 d.openPorts.contains(16509) || d.openPorts.contains(9440)
                 ? Device.Kind.VIRTUALIZATION_HOST : d.kind;

        if (cfg.snmp) {
            for (String comm : cfg.snmpCommunities) {
                try {
                    SnmpScanner.SnmpResult s = SnmpScanner.query(d.ip.getHostAddress(), comm, cfg.snmpTimeoutMs);
                    if (s == null) continue;
                    d.hostname = s.sysName();
                    d.metadata.put("sysDescr", s.sysDescr());
                    d.discoveredBy.add("snmp");
                    String desc = s.sysDescr() == null ? "" : s.sysDescr().toLowerCase();
                    if (desc.contains("router") || desc.contains("ios") || desc.contains("junos"))
                        d.kind = Device.Kind.ROUTER;
                    else if (desc.contains("switch")) d.kind = Device.Kind.SWITCH;
                    // Ek ağlar: routing table'da default olmayanlar
                    for (String dst : s.routes().keySet()) {
                        String cidr = toCidr(dst);
                        if (cidr != null && !cidr.startsWith("0.0.0.0")
                                && !visited.contains(cidr) && cfg.maxSubnets > 0) {
                            NetworkSegment ns = new NetworkSegment(cidr);
                            ns.discoveredBy.add("snmp-route@" + d.ip.getHostAddress());
                            if (visited.size() < cfg.maxSubnets) frontier.add(ns);
                        }
                    }
                    // ARP tablosundan MAC toplama
                    for (var e : s.arpTable().entrySet()) {
                        Device tgt = findOrCreate(byIp, e.getKey());
                        if (tgt.mac == null) tgt.mac = e.getValue();
                        tgt.discoveredBy.add("snmp-arp");
                    }
                    break; // başarılı community
                } catch (Exception ex) {
                    r.warnings.add("snmp@" + d.ip.getHostAddress() + ": " + ex.getMessage());
                }
            }
        }

        // Sanallaştırma tespiti
        String vt = VirtualizationDetector.guessType(d);
        if (vt != null) {
            d.virtualizationType = vt;
            d.kind = Device.Kind.VIRTUALIZATION_HOST;
            VirtualizationHost vh = new VirtualizationHost();
            vh.type = vt; vh.ip = d.ip.getHostAddress(); vh.id = vt + ":" + vh.ip;
            vh.name = d.hostname;
            vh.source = "fingerprint";
            r.vhosts.add(vh);
        }
        String vmv = VirtualizationDetector.vmVendorByMac(d.mac);
        if (vmv != null) d.kind = Device.Kind.VIRTUAL_MACHINE;

        // İşletim sistemi tahmini (SNMP sysDescr + portlar + hostname + OUI)
        if (d.osGuess == null) {
            d.osGuess = OsFingerprint.guess(d);
        }
    }

    // -- yardımcılar ---------------------------------------------------------

    private static Device findOrCreate(Map<String, Device> byIp, String ip) {
        return byIp.computeIfAbsent(ip, key -> {
            Device device = new Device();
            try {
                device.ip = InetAddress.getByName(key);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid SNMP ARP address: " + key, e);
            }
            return device;
        });
    }

    private static VirtualizationHost newHost(DiscoveryConfig.Credential c) {
        VirtualizationHost h = new VirtualizationHost();
        h.id = c.kind + ":" + c.host; h.ip = c.host; h.type = c.kind; h.name = c.host;
        return h;
    }

    private static String toCidr(String dst) {
        String[] parts = dst.split("\\.", -1);
        if (parts.length != 4) return null;
        try {
            for (String part : parts) {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) return null;
            }
            return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void deduplicateVirtualization(DiscoveryResult result) {
        Map<String, VirtualizationHost> hosts = new LinkedHashMap<>();
        for (VirtualizationHost host : result.vhosts) {
            String key = host.ip == null ? host.id : host.ip;
            VirtualizationHost current = hosts.get(key);
            if (current == null || ("api".equals(host.source) && !"api".equals(current.source))) {
                hosts.put(key, host);
            }
        }
        result.vhosts.clear();
        result.vhosts.addAll(hosts.values());

        Map<String, VirtualMachine> vms = new LinkedHashMap<>();
        for (VirtualMachine vm : result.vms) {
            String key = vm.uuid != null ? vm.uuid : vm.mac != null ? vm.mac
                    : vm.hostId + "|" + vm.name;
            vms.putIfAbsent(key, vm);
        }
        result.vms.clear();
        result.vms.addAll(vms.values());
    }

    private static boolean sameCidr(InetAddress ip, String cidr) {
        try {
            String[] p = cidr.split("/");
            InetAddress net = InetAddress.getByName(p[0]);
            int prefix = Integer.parseInt(p[1]);
            int mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
            return (toInt(ip) & mask) == (toInt(net) & mask);
        } catch (Exception e) { return false; }
    }
    private static int toInt(InetAddress a) {
        byte[] b = a.getAddress();
        return ((b[0]&0xFF)<<24)|((b[1]&0xFF)<<16)|((b[2]&0xFF)<<8)|(b[3]&0xFF);
    }

    private static List<InetAddress> expand(String cidr, int max) throws Exception {
        List<InetAddress> out = new ArrayList<>();
        String[] p = cidr.split("/");
        int prefix = Integer.parseInt(p[1]);
        if (prefix < 22) throw new IllegalArgumentException("Çok büyük ağ: " + cidr);
        InetAddress net = InetAddress.getByName(p[0]);
        long base = Integer.toUnsignedLong(toInt(net));
        int size = 1 << (32 - prefix);
        for (int i = 1; i < size - 1 && out.size() < max; i++)
            out.add(InetAddress.getByName(ipStr(base + i)));
        return out;
    }
    private static String ipStr(long v) {
        return ((v>>24)&0xFF)+"."+((v>>16)&0xFF)+"."+((v>>8)&0xFF)+"."+(v&0xFF);
    }

    private static List<String> localIfaces() throws Exception {
        List<String> out = new ArrayList<>();
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces()))
            if (ni.isUp() && !ni.isLoopback()) out.add(ni.getName());
        return out;
    }
    private static String localCidr(String ifName) throws Exception {
        NetworkInterface ni = NetworkInterface.getByName(ifName);
        if (ni == null) return null;
        for (InterfaceAddress ia : ni.getInterfaceAddresses())
            if (ia.getAddress() instanceof Inet4Address) {
                int p = ia.getNetworkPrefixLength();
                InetAddress net = InetAddress.getByName(
                        ipStr((Integer.toUnsignedLong(toInt(ia.getAddress()))
                               & (p==0?0:(0xFFFFFFFF<<(32-p))))));
                return net.getHostAddress() + "/" + p;
            }
        return null;
    }
    private static List<String> localCidrs() throws Exception {
        List<String> out = new ArrayList<>();
        for (String n : localIfaces()) {
            String c = localCidr(n);
            if (c != null) out.add(c);
        }
        return out;
    }
}