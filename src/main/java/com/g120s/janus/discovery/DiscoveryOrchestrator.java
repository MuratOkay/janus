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
    private final RateLimiter limiter;
    private final List<Integer> probePorts = List.of(22,23,53,80,135,139,443,445,902,
            3389,5985,5986,8006,8080,8443,9440,16509);

    public DiscoveryOrchestrator(DiscoveryConfig cfg) {
        this.cfg = cfg;
        this.pool = Executors.newFixedThreadPool(Math.max(2, cfg.threadPool));
        this.limiter = new RateLimiter(cfg.probesPerSecond);
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

        // 1) Seed segments: explicit --cidr values, otherwise every network this host
        // can reach — its interface networks plus whatever its own routing table knows.
        CrawlState state = new CrawlState(r);
        if (cfg.seedCidrs.isEmpty()) {
            for (String cidr : localCidrs()) {
                enqueue(state, new Learned(cidr, false), "local-interface", null, null);
            }
            for (LocalRoutes.Route route : LocalRoutes.read()) {
                enqueue(state, new Learned(route.cidr(), false), "local-route", null, route.gateway());
            }
        } else {
            for (String c : cfg.seedCidrs) {
                enqueue(state, new Learned(c, false), "seed", null, null);
            }
        }

        // 2) BFS
        drain(state);

        // 3) Virtualization APIs (using the supplied credentials)
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
                    // Add the management subnets to the crawl. They come from
                    // operator-supplied credentials, so they are treated as seeds.
                    for (String net : h.managementNets) {
                        enqueue(state, new Learned(net, false), "vm-management@" + h.ip, null, h.ip);
                    }
                }
            } catch (Exception ex) {
                r.warnings.add(c.kind + "@" + c.host + ": " + ex.getMessage());
            }
        }
        // Scan the newly added networks as well
        drain(state);
        r.devices.clear();
        r.devices.addAll(state.byIp.values());

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
                state.byIp.putIfAbsent(device.ip.getHostAddress(), device);
                // A neighbour advertisement names a management address but carries no
                // mask, so the /24 assumption is flagged by toCidr.
                enqueue(state, toCidr(device.ip.getHostAddress(), null), "lldp-mgmt",
                        null, device.ip.getHostAddress());
            }
            drain(state);
            r.devices.clear();
            r.devices.addAll(state.byIp.values());
        }

        deduplicateVirtualization(r);

        // 4) VM ↔ Host matching
        VMHostMatcher.match(r);

        r.finishedAt = System.currentTimeMillis();
        pool.shutdown();
        return r;
    }

    private void discoverHosts(CrawlState state, NetworkSegment seg, List<InetAddress> targets)
            throws Exception {
        Map<String, Device> byIp = state.byIp;
        DiscoveryResult r = state.r;
        // --- TCP sweep
        if (cfg.tcp && !targets.isEmpty()) {
            Map<InetAddress, List<Integer>> scans = new LinkedHashMap<>();
            for (InetAddress ip : targets) {
                scans.put(ip, HostScanners.tcpScan(pool, ip, probePorts, cfg.tcpTimeoutMs, limiter));
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
        if (cfg.icmp && !targets.isEmpty()) {
            for (InetAddress ip : targets) {
                if (HostScanners.icmp(ip, 800, limiter)) {
                    Device d = byIp.computeIfAbsent(ip.getHostAddress(), k -> new Device());
                    d.ip = ip; d.discoveredBy.add("icmp");
                }
            }
        }
        // --- Multicast discovery (once, for the whole segment)
        if (cfg.mdns) {
            try {
                MulticastScanners.MdnsResult mdns = MulticastScanners.mdnsWithNames(2000);
                for (InetAddress ia : mdns.addresses()) {
                    Device d = byIp.computeIfAbsent(ia.getHostAddress(), k -> new Device());
                    d.ip = ia;
                    d.discoveredBy.add("mdns");
                    d.services.add("mdns");
                }
                // Record the host names coming from mDNS
                mdns.names().forEach((ia, name) -> {
                    Device d = byIp.get(ia.getHostAddress());
                    if (d != null) NameResolver.record(d, "mdns", name);
                });
            } catch (Exception e) {
                r.warnings.add("mdns: " + e.getMessage());
            }
        }
        if (cfg.ssdp) {
            try {
                for (var entry : MulticastScanners.ssdpWithHeaders(2000).entrySet()) {
                    InetAddress ia = entry.getKey();
                    Device d = byIp.computeIfAbsent(ia.getHostAddress(), k -> new Device());
                    d.ip = ia;
                    d.discoveredBy.add("ssdp");
                    d.services.add("upnp");
                    String name = NameResolver.fromSsdpHeaders(entry.getValue());
                    if (name != null) NameResolver.record(d, "ssdp", name);
                }
            } catch (Exception e) {
                r.warnings.add("ssdp: " + e.getMessage());
            }
        }
        // --- ARP (only for the local segment)
        if (cfg.arp) {
            try {
                for (String ifName : localIfaces()) {
                    String local = localCidr(ifName);
                    // Compare canonical forms: a seed such as 192.168.68.5/22 must
                    // still match the interface's 192.168.68.0/22.
                    if (local == null || !Cidr.normalize(local).equals(seg.cidr)) continue;
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
        // --- NetBIOS (quick, for every active IP)
        if (cfg.netbios) {
            for (Device d : byIp.values()) {
                if (d.ip == null || d.discoveredBy.contains("netbios")) continue;
                if (!sameCidr(d.ip, seg.cidr)) continue;
                String name = MulticastScanners.netbiosName(d.ip, 250);
                if (name != null) {
                    d.discoveredBy.add("netbios");
                    NameResolver.record(d, "netbios", name);
                }
            }
        }
    }

    /** System information + extra networks (route/ARP) through SNMP. */
    private void enrich(CrawlState state, Device d, NetworkSegment parent) {
        Map<String, Device> byIp = state.byIp;
        DiscoveryResult r = state.r;
        if (d.ip == null) return;
        if (d.vendor == null) {
            String vendor = VirtualizationDetector.vendorByOuiPrefix(d.mac);
            if (!vendor.isEmpty()) d.vendor = vendor;
        }
        d.kind = d.openPorts.contains(902) || d.openPorts.contains(8006) ||
                 d.openPorts.contains(16509) || d.openPorts.contains(9440)
                 ? Device.Kind.VIRTUALIZATION_HOST : d.kind;

        // Name resolution: start with reverse DNS, the most fundamental and accurate source.
        if (cfg.dns) {
            String ptr = NameResolver.reverseDns(d.ip, cfg.dnsServer, cfg.dnsTimeoutMs);
            if (ptr != null) {
                NameResolver.record(d, "ptr", ptr);
                d.discoveredBy.add("dns");
            }
        }

        if (cfg.snmp) {
            for (String comm : cfg.snmpCommunities) {
                try {
                    SnmpScanner.SnmpResult s = SnmpScanner.query(d.ip.getHostAddress(), comm, cfg.snmpTimeoutMs);
                    if (s == null) continue;
                    if (s.sysName() != null && !s.sysName().isBlank()) {
                        NameResolver.record(d, "snmp", s.sysName());
                    }
                    d.metadata.put("sysDescr", s.sysDescr());
                    d.discoveredBy.add("snmp");
                    String desc = s.sysDescr() == null ? "" : s.sysDescr().toLowerCase();
                    if (desc.contains("router") || desc.contains("ios") || desc.contains("junos"))
                        d.kind = Device.Kind.ROUTER;
                    else if (desc.contains("switch")) d.kind = Device.Kind.SWITCH;
                    // Directly attached networks: the most authoritative view of the
                    // router's own subnets, with the real prefix from ipAdEntNetMask.
                    // An interface address is the hop traffic leaves that subnet through.
                    for (var iface : s.ifMasks().entrySet()) {
                        enqueue(state, toCidr(iface.getKey(), iface.getValue()),
                                "snmp-if@" + d.ip.getHostAddress(), parent, iface.getKey());
                    }
                    // Everything the routing table advertises, honouring ipRouteMask
                    // and skipping invalid rows and non-routable networks.
                    for (String dst : s.routes().keySet()) {
                        if (SnmpScanner.ROUTE_TYPE_INVALID.equals(s.routeTypes().get(dst))) continue;
                        Learned learned = toCidr(dst, s.routeMasks().get(dst));
                        if (learned == null || isUnroutable(learned.cidr())) continue;
                        enqueue(state, learned, "snmp-route@" + d.ip.getHostAddress(),
                                parent, s.routes().get(dst));
                    }
                    // Collect MACs from the ARP table, and remember every address the
                    // device proved to exist. These become the probe targets for
                    // --sweep-policy known/sample, which is what makes a /16 tractable.
                    for (var e : s.arpTable().entrySet()) {
                        Device tgt = findOrCreate(byIp, e.getKey());
                        if (tgt.mac == null) tgt.mac = e.getValue();
                        tgt.discoveredBy.add("snmp-arp");
                        collectKnown(state, e.getKey());
                    }
                    // The router's own interface addresses are live hosts too.
                    for (String address : s.ifMasks().keySet()) collectKnown(state, address);
                    s.ipAddresses().forEach(address -> collectKnown(state, address));
                    collectKnown(state, d.ip.getHostAddress());
                    break; // successful community
                } catch (Exception ex) {
                    r.warnings.add("snmp@" + d.ip.getHostAddress() + ": " + ex.getMessage());
                }
            }
        }

        // Virtualization detection
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

        // Operating system guess (SNMP sysDescr + ports + hostname + OUI)
        if (d.osGuess == null) {
            d.osGuess = OsFingerprint.guess(d);
        }

        // Name from the TLS certificate (only if the name is still weak and HTTPS is open)
        if (cfg.tlsNames && !d.hostnamesBySource.containsKey("ptr")
                && !d.hostnamesBySource.containsKey("snmp")) {
            for (int port : new int[]{443, 8443, 9440}) {
                if (!d.openPorts.contains(port)) continue;
                String tlsName = NameResolver.fromTlsCertificate(d.ip, port, cfg.dnsTimeoutMs);
                if (tlsName != null) {
                    NameResolver.record(d, "tls", tlsName);
                    break;
                }
            }
        }
    }

    // -- helpers ---------------------------------------------------------

    /**
     * State of a single crawl. Bundling it keeps the recursive part of the BFS
     * explicit: what is queued, what has been swept, and what was learned where.
     */
    static final class CrawlState {
        final Deque<NetworkSegment> frontier = new ArrayDeque<>();
        final Set<String> visited = new HashSet<>();
        /** Segments already swept, by CIDR, used for containment suppression. */
        final Map<String, NetworkSegment> swept = new LinkedHashMap<>();
        /**
         * Addresses proven to exist, harvested from SNMP interface and ARP tables.
         * This is what makes {@link SweepPolicy#KNOWN} possible: a router already
         * knows who is on its subnets.
         */
        final Set<String> knownHosts = new HashSet<>();
        final Map<String, Device> byIp = new HashMap<>();
        final DiscoveryResult r;
        int generated;

        CrawlState(DiscoveryResult r) {
            this.r = r;
        }
    }

    /** Crawls queued segments until the queue empties or {@code maxSubnets} is hit. */
    private void drain(CrawlState state) {
        while (!state.frontier.isEmpty() && state.generated < cfg.maxSubnets) {
            NetworkSegment seg = state.frontier.poll();
            if (!state.visited.add(seg.cidr)) continue;
            state.generated++;
            NetworkSegment covering = coveringSegment(state, seg.cidr);
            if (covering != null) {
                // A wider network was already swept end to end, so this range holds
                // no host that has not been seen. It is still recorded: the subnet
                // inventory must stay complete even when a sweep is skipped.
                seg.coveredBy = covering.cidr;
                state.r.segments.add(seg);
                continue;
            }
            state.swept.put(seg.cidr, seg);
            crawlSegment(state, seg);
        }
        state.r.devices.clear();
        state.r.devices.addAll(state.byIp.values());
    }

    /**
     * Finds an already swept segment that fully contains {@code cidr}. Only
     * segments that were probed to completion count: a truncated sweep leaves
     * parts of its range unexamined, so it cannot stand in for a narrower network.
     */
    static NetworkSegment coveringSegment(CrawlState state, String cidr) {
        for (NetworkSegment swept : state.swept.values()) {
            if (swept.cidr.equals(cidr) || !fullyScanned(swept)) continue;
            if (Cidr.contains(swept.cidr, cidr)) return swept;
        }
        return null;
    }

    /** Did the sweep cover every usable address of the segment? */
    static boolean fullyScanned(NetworkSegment seg) {
        return seg.hostsTotal > 0 && seg.hostsProbed >= seg.hostsTotal;
    }

    /**
     * Crawls one segment. A failure is recorded as a warning instead of being
     * propagated: one unparseable or unreachable segment must never abort the run.
     */
    private void crawlSegment(CrawlState state, NetworkSegment seg) {
        state.r.segments.add(seg);
        try {
            List<InetAddress> targets = List.of();
            if (cfg.tcp || cfg.icmp) {
                targets = hostsToProbe(state, seg);
                seg.hostsProbed = targets.size();
                seg.hostsTotal = Cidr.usableHosts(seg.cidr);
                seg.sweepPolicy = cfg.sweepPolicy.name().toLowerCase(java.util.Locale.ROOT);
            }
            // 2a) Host discovery (parallel strategies)
            discoverHosts(state, seg, targets);
            // 2b) Services + SNMP for every active device on this segment. The map is
            // copied first because enrichment adds devices harvested from ARP tables.
            for (Device d : List.copyOf(state.byIp.values())) {
                if (d.ip == null || !sameCidr(d.ip, seg.cidr)) continue;
                enrich(state, d, seg);
            }
        } catch (Exception e) {
            state.r.warnings.add("segment " + seg.cidr + ": " + e.getMessage());
        }
    }

    /**
     * Queues a candidate subnet for crawling in canonical form. Duplicates,
     * malformed values, ranges below the minimum prefix and networks beyond the
     * depth limit are dropped; the last two are reported so an operator can see
     * why a discovered network was not visited.
     */
    void enqueue(CrawlState state, Learned learned, String source,
                 NetworkSegment parent, String gateway) {
        if (learned == null || learned.cidr() == null || !learned.cidr().contains("/")) return;
        String normalized;
        try {
            normalized = Cidr.normalize(learned.cidr());
        } catch (IllegalArgumentException e) {
            state.r.warnings.add("ignored invalid segment " + learned.cidr() + " from " + source);
            return;
        }
        if (Cidr.prefix(normalized) < Cidr.MIN_PREFIX) {
            state.r.warnings.add("ignored oversized segment " + normalized + " from " + source);
            return;
        }
        int depth = parent == null ? 0 : parent.depth + 1;
        if (depth > cfg.maxDepth) {
            String warning = "depth limit " + cfg.maxDepth + " reached: " + normalized
                    + " from " + source + " was not crawled (raise --max-depth)";
            if (!state.r.warnings.contains(warning)) state.r.warnings.add(warning);
            return;
        }
        if (state.visited.contains(normalized) || queued(state, normalized)) return;
        if (state.visited.size() + state.frontier.size() >= cfg.maxSubnets) return;
        NetworkSegment segment = new NetworkSegment(normalized);
        segment.depth = depth;
        segment.parentCidr = parent == null ? null : parent.cidr;
        segment.gateway = gateway;
        segment.discoveredBy.add(source);
        if (learned.maskAssumed()) segment.discoveredBy.add(source + "-mask-assumed");
        state.frontier.add(segment);
    }

    private static boolean queued(CrawlState state, String cidr) {
        for (NetworkSegment pending : state.frontier) {
            if (pending.cidr.equals(cidr)) return true;
        }
        return false;
    }

    /** Default routes, loopback, link-local and multicast ranges are never crawled. */
    static boolean isUnroutable(String cidr) {
        return cidr.startsWith("0.0.0.0") || cidr.startsWith("127.")
                || cidr.startsWith("169.254.") || cidr.startsWith("224.")
                || cidr.startsWith("239.") || cidr.startsWith("255.");
    }

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

    /**
     * A subnet learned from an external source, and whether its prefix had to be
     * guessed because the source did not provide a netmask.
     */
    record Learned(String cidr, boolean maskAssumed) {}

    /**
     * Builds a CIDR from an address and the netmask that came with it. When the
     * mask is missing or unusable the address is assumed to be a /24 and the result
     * is flagged, so an assumed prefix stays visible in the report instead of
     * silently reshaping the network.
     */
    static Learned toCidr(String addr, String mask) {
        String exact = Cidr.fromMask(addr, mask);
        if (exact != null) return new Learned(exact, false);
        if (Cidr.parseIp(addr) == null) return null;
        return new Learned(Cidr.normalize(addr + "/24"), true);
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
        return ip != null && Cidr.contains(cidr, ip.getHostAddress() + "/32");
    }
    private static int toInt(InetAddress a) {
        byte[] b = a.getAddress();
        return ((b[0]&0xFF)<<24)|((b[1]&0xFF)<<16)|((b[2]&0xFF)<<8)|(b[3]&0xFF);
    }

    /** The addresses of a segment that will actually be probed. */
    record Expansion(List<InetAddress> addresses, long subnetSize, boolean truncated) {}

    /**
     * Expands a segment into the addresses to probe. Very large ranges are capped
     * at {@code maxHosts} rather than rejected: a /16 is a normal enterprise subnet
     * and must produce a bounded scan, not an abort.
     */
    static Expansion expand(String cidr, int maxHosts) throws Exception {
        String[] p = cidr.split("/");
        int prefix = Integer.parseInt(p[1]);
        InetAddress net = InetAddress.getByName(p[0]);
        long base = Integer.toUnsignedLong(toInt(net));
        long size = 1L << (32 - prefix);
        long usable = Math.max(0, size - 2);   // network and broadcast are not hosts
        List<InetAddress> out = new ArrayList<>();
        for (long i = 1; i < size - 1 && out.size() < maxHosts; i++) {
            out.add(InetAddress.getByName(ipStr(base + i)));
        }
        return new Expansion(List.copyOf(out), usable, usable > out.size());
    }

    /**
     * Reports a capped expansion once per segment, so the operator knows a subnet
     * was only partially probed instead of assuming it is empty.
     */
    /**
     * Chooses which addresses of a segment to probe. Under {@code FULL} this is the
     * whole range (capped); under {@code KNOWN} only addresses a router reported;
     * under {@code SAMPLE} the known ones plus a deterministic sample spanning the
     * range, so a large subnet is characterised without being swept.
     */
    List<InetAddress> hostsToProbe(CrawlState state, NetworkSegment seg) throws Exception {
        if (cfg.sweepPolicy == SweepPolicy.FULL) {
            Expansion full = expand(seg.cidr, cfg.maxHostsPerSubnet);
            warnIfTruncated(seg, full, state.r);
            return full.addresses();
        }

        List<InetAddress> known = knownHostsIn(state, seg);
        if (cfg.sweepPolicy == SweepPolicy.KNOWN) {
            if (known.isEmpty()) {
                addWarningOnce(state.r, "segment " + seg.cidr
                        + ": no SNMP host data, so nothing was probed under"
                        + " --sweep-policy known (use sample or full)");
            } else if (known.size() > cfg.maxHostsPerSubnet) {
                addWarningOnce(state.r, "segment " + seg.cidr + ": " + known.size()
                        + " known hosts, probing the first " + cfg.maxHostsPerSubnet
                        + " (raise --max-hosts-per-subnet)");
                known = known.subList(0, cfg.maxHostsPerSubnet);
            }
            return List.copyOf(known);
        }

        // SAMPLE: everything known, plus the gateway hop, plus a spread of the range.
        LinkedHashSet<String> addresses = new LinkedHashSet<>();
        known.forEach(ip -> addresses.add(ip.getHostAddress()));
        if (seg.gateway != null && Cidr.contains(seg.cidr, seg.gateway + "/32")) {
            addresses.add(seg.gateway);
        }
        for (InetAddress sampled : sampleAddresses(seg.cidr, cfg.sampleHostsPerSubnet)) {
            addresses.add(sampled.getHostAddress());
        }
        List<InetAddress> targets = new ArrayList<>();
        for (String address : addresses) {
            if (targets.size() >= cfg.maxHostsPerSubnet) break;
            targets.add(InetAddress.getByName(address));
        }
        return targets;
    }

    /** Addresses harvested from SNMP tables that fall inside {@code seg}. */
    private static List<InetAddress> knownHostsIn(CrawlState state, NetworkSegment seg) throws Exception {
        List<Long> values = new ArrayList<>();
        for (String ip : state.knownHosts) {
            Long value = Cidr.parseIp(ip);
            if (value == null || !Cidr.contains(seg.cidr, ip + "/32")) continue;
            values.add(value);
        }
        Collections.sort(values);
        List<InetAddress> out = new ArrayList<>(values.size());
        for (long value : values) out.add(InetAddress.getByName(Cidr.toIp(value)));
        return out;
    }

    /**
     * Picks {@code count} distinct addresses from across the whole range. The seed is
     * derived from the CIDR so repeated runs sample the same hosts and results stay
     * comparable between scans.
     */
    static List<InetAddress> sampleAddresses(String cidr, int count) throws Exception {
        String[] parts = cidr.split("/");
        int prefix = Integer.parseInt(parts[1]);
        Long network = Cidr.parseIp(parts[0]);
        if (network == null) return List.of();
        long usable = (1L << (32 - prefix)) - 2;
        if (usable <= 0 || count <= 0) return List.of();
        int want = (int) Math.min(count, usable);
        Random random = new Random(cidr.hashCode());
        Set<Long> offsets = new HashSet<>();
        for (int guard = 0; offsets.size() < want && guard < want * 20; guard++) {
            long offset = 1 + (long) (random.nextDouble() * usable);
            offsets.add(Math.max(1, Math.min(usable, offset)));
        }
        List<Long> sorted = new ArrayList<>(offsets);
        Collections.sort(sorted);
        List<InetAddress> out = new ArrayList<>(sorted.size());
        for (long offset : sorted) out.add(InetAddress.getByName(ipStr(network + offset)));
        return out;
    }

    private static void addWarningOnce(DiscoveryResult r, String warning) {
        if (!r.warnings.contains(warning)) r.warnings.add(warning);
    }

    /** Records a live address reported by a device, ignoring anything malformed. */
    static void collectKnown(CrawlState state, String address) {
        if (address == null) return;
        Long value = Cidr.parseIp(address);
        if (value == null) return;
        String canonical = Cidr.toIp(value);
        if (canonical.equals("0.0.0.0")) return;
        state.knownHosts.add(canonical);
    }

    private static void warnIfTruncated(NetworkSegment seg, Expansion expansion, DiscoveryResult r) {
        if (!expansion.truncated()) return;
        addWarningOnce(r, "segment " + seg.cidr + " holds " + expansion.subnetSize()
                + " addresses; only the first " + expansion.addresses().size()
                + " were probed (raise --max-hosts-per-subnet)");
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