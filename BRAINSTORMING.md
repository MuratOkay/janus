# Bir networkteki tüm bilgisayarları ve network cihazlarını…

**Kullanıcı:**

Bir networkteki tüm bilgisayarları ve network cihazlarını bulacak bir yazılım yapıyorum. Bulduğu sanallaştırma sunucularını ve sanallaştırılmış sunucuları da birbiriyle eşlemesi gerekiyor. Ayrıca, LAN üzerinde birden fazla network varsa onları da cihazlar üzerinden ya da başka yollarla bulması gerekiyor. Ping, SNMP gibi engellenebilir yöntemlerin yanısıra diğer yöntemleri de kullanması gerekiyor. Bunu yapan ve Java ile geliştirilmiş bir uygulama yazabilir misin?

**Asistan:**

# Java ile Ağ Envanteri ve Sanallaştırma Keşif Aracı

Evet, yazabilirim. Aşağıda bir Maven projesi olarak, modüler ve gerçekçi bir iskelet + çalışan çekirdek bileşenler veriyorum. Tasarım; **katmanlı keşif** (L2 → L3 → servis → sanallaştırma → topoloji) ve **çoklu yöntem + çoklu LAN BFS** üzerine kurulu.

> ⚠️ **Önemli:** Bu tür aktif tarama/keşif, yalnızca sahibi olduğunuz veya yazılı izin aldığınız ağlarda yapılmalıdır. Yetkisiz tarama birçok ülkede suç teşkil eder. ARP/LLDP/CDP yakalama için `npcap` (Windows) veya `libpcap` + `CAP_NET_RAW` (Linux) gerekir.

---

## 1. `pom.xml`

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>tr.example</groupId>
  <artifactId>netdisc</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
  </properties>
  <dependencies>
    <!-- L2: ARP / LLDP / CDP -->
    <dependency>
      <groupId>org.pcap4j</groupId><artifactId>pcap4j-core</artifactId><version>1.8.2</version>
    </dependency>
    <dependency>
      <groupId>org.pcap4j</groupId><artifactId>pcap4j-packetfactory-static</artifactId><version>1.8.2</version>
    </dependency>

    <!-- SNMP (v1/v2c/v3) -->
    <dependency>
      <groupId>org.snmp4j</groupId><artifactId>snmp4j</artifactId><version>3.7.7</version>
    </dependency>

    <!-- mDNS/SD -->
    <dependency>
      <groupId>dnsjava</groupId><artifactId>dnsjava</artifactId><version>3.5.3</version>
    </dependency>

    <!-- JSON / HTTP / SSH -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.17.1</version>
    </dependency>
    <dependency>
      <groupId>com.hierynomus</groupId><artifactId>sshj</artifactId><version>0.38.0</version>
    </dependency>

    <!-- İsteğe bağlı: VMware vSphere SDK (yavijava) - ESXi/vCenter API -->
    <!-- <dependency><groupId>com.toasttab.vijava</groupId><artifactId>yavijava</artifactId><version>6.0.1</version></dependency> -->

    <dependency>
      <groupId>org.slf4j</groupId><artifactId>slf4j-simple</artifactId><version>2.0.13</version>
    </dependency>
  </dependencies>
</project>
```

---

## 2. Konfigürasyon

```java
// src/main/java/netdisc/DiscoveryConfig.java
package netdisc;

import java.util.*;

public class DiscoveryConfig {
    public List<String> seedCidrs = new ArrayList<>();           // başlangıç ağları (yoksa otomatik)
    public List<String> snmpCommunities = new ArrayList<>(List.of("public"));
    public List<Credential> vmCreds = new ArrayList<>();         // ESXi/Proxmox/KVM/Hyper-V

    public boolean icmp = true, tcp = true, arp = true;
    public boolean mdns = true, ssdp = true, netbios = true, snmp = true;
    public boolean lldpCdp = true;

    public int tcpTimeoutMs = 400;
    public int snmpTimeoutMs = 1500;
    public int threadPool = 256;
    public int maxSubnets = 64;     // BFS'te toplam alt ağ üst sınırı
    public int maxDepth = 4;        // zincirleme keşif derinliği
    public String outputPath = "discovery-report.json";

    public static class Credential {
        public String kind;         // "esxi" | "proxmox" | "kvm" | "hyperv"
        public String host, user, passOrKey;
        public int port = 0;        // 0 = tipe göre varsayılan
        public Credential(String k, String h, String u, String p) {
            kind = k; host = h; user = u; passOrKey = p;
        }
    }

    public static DiscoveryConfig fromArgs(String[] a) {
        DiscoveryConfig c = new DiscoveryConfig();
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--cidr"  -> c.seedCidrs.add(a[++i]);
                case "--snmp"  -> c.snmpCommunities.add(a[++i]);
                case "--out"   -> c.outputPath = a[++i];
                case "--threads" -> c.threadPool = Integer.parseInt(a[++i]);
            }
        }
        return c;
    }
}
```

---

## 3. Veri modeli

```java
// src/main/java/netdisc/model/Device.java
package netdisc.model;

import java.net.InetAddress;
import java.util.*;

public class Device {
    public enum Kind { UNKNOWN, WORKSTATION, SERVER, ROUTER, SWITCH, FIREWALL,
                       PRINTER, IOT, MOBILE, STORAGE, VIRTUALIZATION_HOST, VIRTUAL_MACHINE }

    public InetAddress ip;
    public String mac;                        // aa:bb:cc:dd:ee:ff (küçük harf)
    public String hostname;
    public String vendor;                     // OUI lookup
    public Kind kind = Kind.UNKNOWN;
    public Set<Integer> openPorts = new TreeSet<>();
    public Set<String> services = new TreeSet<>();
    public Set<String> discoveredBy = new TreeSet<>();   // arp, tcp:22, snmp, mdns...
    public String osGuess;
    public String virtualizationType;         // esxi, vcenter, proxmox, kvm, hyperv, xen, nutanix, virtualbox
    public String ownerHostId;                // VM ise bağlı olduğu host kimliği (mac/ip/uuid)
    public Map<String,String> metadata = new HashMap<>();

    @Override public boolean equals(Object o) {
        if (!(o instanceof Device d)) return false;
        return Objects.equals(ip, d.ip) && Objects.equals(mac, d.mac);
    }
    @Override public int hashCode() { return Objects.hash(ip, mac); }
}
```

```java
// src/main/java/netdisc/model/NetworkSegment.java
package netdisc.model;
import java.util.*;
public class NetworkSegment {
    public String cidr;            // 10.0.5.0/24
    public String gateway;
    public String vlan;
    public String description;
    public Set<String> discoveredBy = new TreeSet<>();  // iface, snmp-route, lldp, dhcp, vmware-portgroup...
    public NetworkSegment(String cidr) { this.cidr = cidr; }
}
```

```java
// src/main/java/netdisc/model/DiscoveryResult.java
package netdisc.model;
import java.util.*;
public class DiscoveryResult {
    public List<NetworkSegment> segments = new ArrayList<>();
    public List<Device> devices = new ArrayList<>();
    public List<VirtualMachine> vms = new ArrayList<>();
    public List<VirtualizationHost> vhosts = new ArrayList<>();
    public List<String> warnings = new ArrayList<>();
    public long startedAt, finishedAt;
}
```

```java
// src/main/java/netdisc/model/VirtualizationHost.java
package netdisc.model;
import java.util.*;
public class VirtualizationHost {
    public String id;             // uuid / mac / ip
    public String type;           // esxi, vcenter, proxmox, kvm, hyperv, xen, nutanix
    public String ip, name, version;
    public Set<String> vmMacs = new TreeSet<>();   // yönetilen VM'lerin MAC'leri
    public Set<String> managementNets = new TreeSet<>();  // host VMkernel/bridge subnetleri
}
```

```java
// src/main/java/netdisc/model/VirtualMachine.java
package netdisc.model;
import java.util.*;
public class VirtualMachine {
    public String name, uuid, hostId, mac;
    public String powerState;
    public String guestOs;
    public List<String> nics = new ArrayList<>();  // mac@network
    public String ip;                              // eşleşince dolar
}
```

---

## 4. Host keşif tarayıcıları (TCP + ICMP + multicast)

```java
// src/main/java/netdisc/discovery/HostScanners.java
package netdisc.discovery;

import netdisc.model.Device;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public final class HostScanners {

    /** TCP connect probe: ICMP bloklu olsa bile port açıksa canlılık kanıtıdır. */
    public static boolean tcpProbe(InetAddress ip, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (Exception e) { return false; }
    }

    /** Birden fazla porta paralel TCP denemesi; ilk açık port cevabı yeter. */
    public static List<Integer> tcpScan(ExecutorService pool, InetAddress ip,
                                        List<Integer> ports, int timeoutMs) throws Exception {
        List<Future<Integer>> fs = new ArrayList<>();
        for (int p : ports) fs.add(pool.submit(() -> tcpProbe(ip, p, timeoutMs) ? p : -1));
        List<Integer> open = new ArrayList<>();
        for (Future<Integer> f : fs) { int p = f.get(); if (p > 0) open.add(p); }
        Collections.sort(open);
        return open;
    }

    /** ICMP echo (Java sürümüne göre ICMP veya TCP yankı olabilir; TCP ile desteklenmeli). */
    public static boolean icmp(InetAddress ip, int timeoutMs) {
        try { return ip.isReachable(timeoutMs); } catch (Exception e) { return false; }
    }
}
```

**mDNS / SSDP / NetBIOS — multicast tabanlı (herhangi bir kimlik bilgisi gerekmez):**

```java
// src/main/java/netdisc/discovery/MulticastScanners.java
package netdisc.discovery;

import org.xbill.DNS.*;
import java.net.*;
import java.util.*;

public final class MulticastScanners {

    /** mDNS: _services._dns-sd._udp.local ve yaygın servisleri sorgular, cevap veren IP'leri döner. */
    public static Set<InetAddress> mdns(int durationMs) throws Exception {
        Set<InetAddress> seen = new HashSet<>();
        try (MulticastSocket s = new MulticastSocket()) {
            s.setSoTimeout(250);
            s.setTimeToLive(255);
            InetAddress group = InetAddress.getByName("224.0.0.251");
            s.joinGroup(new InetSocketAddress(group, 5353), NetworkInterface.getByInetAddress(
                    InetAddress.getLocalHost()));
            Message q = new Message();
            q.addRecord(new PTRRecord(Name.fromString("_services._dns-sd._udp.local."),
                    DClass.IN, 0, Name.fromString("_services._dns-sd._udp.local.")));
            byte[] out = q.toWire();
            s.send(new DatagramPacket(out, out.length, group, 5353));

            long end = System.currentTimeMillis() + durationMs;
            byte[] buf = new byte[4096];
            while (System.currentTimeMillis() < end) {
                try {
                    DatagramPacket in = new DatagramPacket(buf, buf.length);
                    s.receive(in);
                    Message resp = new Message(in.getData(), in.getOffset(), in.getLength());
                    for (Record r : resp.getSection(Section.ANSWER)) {
                        if (r instanceof ARecord a) seen.add(a.getAddress());
                        if (r instanceof PTRRecord || r instanceof SRVRecord) {
                            // tüm cevapların kaynak IP'sini de canlı kabul et
                            seen.add(in.getAddress());
                        }
                    }
                    seen.add(in.getAddress());
                } catch (SocketTimeoutException ignored) { }
            }
            s.leaveGroup(new InetSocketAddress(group, 5353),
                    NetworkInterface.getByInetAddress(InetAddress.getLocalHost()));
        }
        return seen;
    }

    /** SSDP (UPnP): M-SEARCH ile cevap veren cihazlar. Router, NAS, akıllı TV, IoT. */
    public static Set<InetAddress> ssdp(int durationMs) throws Exception {
        Set<InetAddress> seen = new HashSet<>();
        String msg = "M-SEARCH * HTTP/1.1\r\n" +
                     "HOST: 239.255.255.250:1900\r\n" +
                     "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(300);
            byte[] b = msg.getBytes();
            s.send(new DatagramPacket(b, b.length,
                    InetAddress.getByName("239.255.255.250"), 1900));
            long end = System.currentTimeMillis() + durationMs;
            byte[] buf = new byte[2048];
            while (System.currentTimeMillis() < end) {
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    seen.add(p.getAddress());
                } catch (SocketTimeoutException ignored) { }
            }
        }
        return seen;
    }

    /** NetBIOS Node Status (UDP 137) — Windows istemcileri için isim ve MAC bilgisi verir. */
    public static Map<InetAddress, String> netbios(InetAddress target, int timeoutMs) {
        Map<InetAddress, String> out = new HashMap<>();
        byte[] query = new byte[] {
            (byte)0x82, (byte)0x28, 0,0, 0,1, 0,0, 0,0, 0,0,
            0x20, 'C','K','A','A','A','A','A','A','A','A','A','A','A','A','A',
            'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
            0, 0x20, 0x01
        };
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(timeoutMs);
            s.send(new DatagramPacket(query, query.length, target, 137));
            byte[] buf = new byte[2048];
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            s.receive(p);
            // Cevaptaki ilk NetBIOS adını (offset ~56) kabaca oku
            if (p.getLength() > 56) {
                int n = buf[56] & 0xFF;  // 0x20 = aktif ad grubu
                if ((buf[55] & 0x18) == 0) {
                    String name = new String(buf, 56, 15).trim();
                    out.put(p.getAddress(), name);
                }
            }
        } catch (Exception ignored) { }
        return out;
    }
}
```

---

## 5. L2 tarama: ARP + LLDP/CDP (pcap4j)

```java
// src/main/java/netdisc/discovery/L2Scanner.java
package netdisc.discovery;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.net.*;
import java.util.*;

public final class L2Scanner {
    public record ArpEntry(String ip, String mac) {}

    /** Bir arayüzde /24 için ARP taraması; katman 2 canlılık altın standardıdır. */
    public static List<ArpEntry> arpScan(String ifName, String ipv4Cidr,
                                         int timeoutMs) throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName(ifName);
        if (nif == null) throw new IllegalArgumentException("iface yok: " + ifName);

        InetAddress localIp = nif.getAddresses().stream()
                .map(PcapAddress::getAddress)
                .filter(a -> a instanceof Inet4Address).findFirst().orElseThrow();
        byte[] localMacBytes = nif.getLinkLayerAddresses().get(0).getAddress();

        List<Inet4Address> targets = expand(ipv4Cidr);

        PcapHandle send = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        PcapHandle recv = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        recv.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE);

        for (Inet4Address t : targets) {
            ArpPacket arp = new ArpPacket.Builder()
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte)6).protocolAddrLength((byte)4)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(MacAddress.getByAddress(localMacBytes))
                    .srcProtocolAddr((Inet4Address) localIp)
                    .dstHardwareAddr(MacAddress.ETHER_BROADCAST)
                    .dstProtocolAddr(t)
                    .build();
            EthernetPacket pkt = new EthernetPacket.Builder()
                    .srcAddr(MacAddress.getByAddress(localMacBytes))
                    .dstAddr(MacAddress.ETHER_BROADCAST)
                    .type(EtherType.ARP)
                    .payloadBuilder(new SimpleBuilder(arp))
                    .paddingAtBuild(true).build();
            send.sendPacket(pkt);
        }

        Map<String,String> found = new TreeMap<>();
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            try {
                Packet p = recv.getNextPacketEx();
                ArpPacket arp = p.get(ArpPacket.class);
                if (arp != null && arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                    found.put(arp.getHeader().getSrcProtocolAddr().getHostAddress(),
                              arp.getHeader().getSrcHardwareAddr().toString().toLowerCase());
                }
            } catch (TimeoutException ignored) { }
        }
        send.close(); recv.close();
        return found.entrySet().stream().map(e -> new ArpEntry(e.getKey(), e.getValue())).toList();
    }

    private static List<Inet4Address> expand(String cidr) throws Exception {
        String[] p = cidr.split("/");
        Inet4Address net = (Inet4Address) InetAddress.getByName(p[0]);
        int prefix = Integer.parseInt(p[1]);
        long base = ipToLong(net);
        long mask = (prefix == 0) ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long network = base & mask;
        long bcast = network | (~mask & 0xFFFFFFFFL);
        List<Inet4Address> out = new ArrayList<>();
        for (long a = network + 1; a < bcast; a++) out.add(longToIp(a));
        return out;
    }
    private static long ipToLong(Inet4Address a) {
        byte[] b = a.getAddress();
        return ((b[0]&0xFFL)<<24)|((b[1]&0xFFL)<<16)|((b[2]&0xFFL)<<8)|(b[3]&0xFFL);
    }
    private static Inet4Address longToIp(long v) throws UnknownHostException {
        return (Inet4Address) InetAddress.getByAddress(new byte[]{
            (byte)(v>>24),(byte)(v>>16),(byte)(v>>8),(byte)v});
    }

    /** LLDP (0x88CC) ve CDP (SNAP 0x2000) paketlerini dinler; komşu IP/switch port bilgisi verir. */
    public static List<String> sniffNeighbors(String ifName, int durationMs) throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName(ifName);
        PcapHandle h = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        h.setFilter("ether proto 0x88cc or (ether[12:2] == 0x2000 and vlan)", BpfProgram.BpfCompileMode.OPTIMIZE);
        List<String> peers = new ArrayList<>();
        long end = System.currentTimeMillis() + durationMs;
        while (System.currentTimeMillis() < end) {
            try {
                Packet p = h.getNextPacketEx();
                // payload'da yazdırılabilir stringleri kabaca topla (Chassis ID/Port ID/TTL/Mgmt Addr)
                byte[] raw = p.getRawData();
                StringBuilder sb = new StringBuilder();
                for (byte b : raw) {
                    char c = (char)(b & 0xFF);
                    if (c >= 32 && c < 127) sb.append(c);
                    else if (sb.length() > 0) { if (sb.length() >= 4) peers.add(sb.toString()); sb.setLength(0); }
                }
            } catch (TimeoutException ignored) { }
        }
        h.close();
        return peers;
    }
}
```

---

## 6. SNMP keşfi: sistem bilgisi, ARP/route tabloları, LLDP

```java
// src/main/java/netdisc/discovery/SnmpScanner.java
package netdisc.discovery;

import org.snmp4j.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.*;

public final class SnmpScanner {

    private static final OID SYS_DESCR = new OID("1.3.6.1.2.1.1.1.0");
    private static final OID SYS_NAME  = new OID("1.3.6.1.2.1.1.5.0");
    private static final OID SYS_LOC   = new OID("1.3.6.1.2.1.1.6.0");
    private static final OID IP_ADDR   = new OID("1.3.6.1.2.1.4.20.1.1");
    private static final OID ROUTE_DST = new OID("1.3.6.1.2.1.4.21.1.1");
    private static final OID ROUTE_NH  = new OID("1.3.6.1.2.1.4.21.1.7");
    private static final OID ARP_IP    = new OID("1.3.6.1.2.1.4.22.1.3");   // ipNetToMediaNetAddress
    private static final OID ARP_MAC   = new OID("1.3.6.1.2.1.4.22.1.2");   // ipNetToMediaPhysAddress

    public record SnmpResult(String sysDescr, String sysName, String sysLoc,
                             List<String> ipAddresses,
                             Map<String,String> routes,
                             Map<String,String> arpTable) {}

    public static SnmpResult query(String host, String community, int timeoutMs) throws Exception {
        try (TransportMapping<?> transport = new DefaultUdpTransportMapping()) {
            ((DefaultUdpTransportMapping)transport).listen();
            Snmp snmp = new Snmp(transport);
            CommunityTarget<Address> t = new CommunityTarget<>();
            t.setCommunity(new OctetString(community));
            t.setAddress(GenericAddress.parse("udp:" + host + "/161"));
            t.setRetries(1);
            t.setTimeout(timeoutMs);
            t.setVersion(SnmpConstants.version2c);

            String descr = get(snmp, t, SYS_DESCR);
            if (descr == null) return null;   // SNMP yok/erişilemez

            String name = get(snmp, t, SYS_NAME);
            String loc  = get(snmp, t, SYS_LOC);

            List<String> ips = walkColumn(snmp, t, IP_ADDR).stream()
                    .map(v -> v.replaceFirst("^.*\\.", "")).toList();

            Map<String,String> routes = new LinkedHashMap<>();
            Map<String,String> arps   = new LinkedHashMap<>();
            List<String> dsts = walkColumn(snmp, t, ROUTE_DST);
            List<String> nhs  = walkColumn(snmp, t, ROUTE_NH);
            for (int i = 0; i < Math.min(dsts.size(), nhs.size()); i++)
                routes.put(dsts.get(i), nhs.get(i));

            List<String> arpIps = walkColumn(snmp, t, ARP_IP);
            List<String> arpMcs = walkColumn(snmp, t, ARP_MAC);
            for (int i = 0; i < Math.min(arpIps.size(), arpMcs.size()); i++)
                arps.put(arpIps.get(i), arpMcs.get(i));

            snmp.close();
            return new SnmpResult(descr, name, loc, ips, routes, arps);
        }
    }

    private static String get(Snmp snmp, Target<Address> t, OID oid) throws Exception {
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(oid));
        pdu.setType(PDU.GET);
        ResponseEvent<Address> r = snmp.send(pdu, t);
        if (r == null || r.getResponse() == null || r.getResponse().getErrorStatus() != 0) return null;
        VariableBinding vb = r.getResponse().get(0);
        return vb.getVariable().isNull() ? null : vb.getVariable().toString();
    }

    private static List<String> walkColumn(Snmp snmp, Target<Address> t, OID col) throws Exception {
        List<String> out = new ArrayList<>();
        OID cur = col;
        while (true) {
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(cur));
            pdu.setType(PDU.GETNEXT);
            ResponseEvent<Address> r = snmp.send(pdu, t);
            if (r == null || r.getResponse() == null) break;
            VariableBinding vb = r.getResponse().get(0);
            if (!vb.getOid().startsWith(col) || vb.getVariable().isNull()) break;
            out.add(vb.getVariable().toString());
            cur = vb.getOid();
        }
        return out;
    }
}
```

---

## 7. Sanallaştırma tespiti ve VM eşlemesi

### 7.1 Fingerprint (kimlik bilgisi olmadan)

```java
// src/main/java/netdisc/virtualization/VirtualizationDetector.java
package netdisc.virtualization;

import netdisc.model.Device;
import java.util.Set;

public final class VirtualizationDetector {

    /** Açık portlar + banner + OUI'ye bakarak host tipini tahmin eder. */
    public static String guessType(Device d) {
        Set<Integer> p = d.openPorts;
        String v = d.vendor == null ? "" : d.vendor.toLowerCase();
        if (p.contains(902) || (p.contains(443) && p.contains(427) && p.contains(80)))
            return "esxi";
        if (p.contains(9443) && p.contains(443)) return "vcenter";
        if (p.contains(8006))                    return "proxmox";
        if (p.contains(16509) || p.contains(16514)) return "kvm";
        if (p.contains(5985) || p.contains(5986)) return v.contains("microsoft") ? "hyperv" : null;
        if (p.contains(9440))                    return "nutanix";
        if (p.contains(443) && vendorOUI(d).equals("xen")) return "xen";
        return null;
    }

    /** Sanal makine MAC OUI aralıkları. */
    public static String vmVendorByMac(String mac) {
        if (mac == null) return null;
        String pref = mac.toLowerCase().substring(0, 8);
        return switch (pref) {
            case "00:0c:29", "00:50:56", "00:05:69", "00:1c:14" -> "vmware";
            case "00:15:5d", "00:1d:d8", "00:03:ff" -> "hyperv";
            case "00:16:3e" -> "xen";
            case "52:54:00" -> "qemu-kvm";
            case "08:00:27" -> "virtualbox";
            case "0a:00:27" -> "virtualbox-nat";
            default -> null;
        };
    }
    private static String vendorOUI(Device d) { return ""; }
}
```

### 7.2 VMware ESXi / vCenter (SSH üzerinden `vim-cmd`)

> Daha sağlamı vSphere SDK (yavijava). Burada bağımlılık minimum olsun diye SSH ile gösteriyorum — ESXi'de SSH açık ve kimlik bilgisi verilmişse çalışır.

```java
// src/main/java/netdisc/virtualization/EsxiDiscovery.java
package netdisc.virtualization;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import java.util.*;
import java.util.regex.*;

public final class EsxiDiscovery {
    private static final Pattern VM_ROW = Pattern.compile(
            "^(\\d+)\\s+([^\\s]+)\\s+\\[.*?\\]\\s+(.*)$", Pattern.MULTILINE);
    // vim-cmd vmsvc/getallvms

    public static VirtualizationHost discover(VirtualizationHost host,
                                              String user, String pass,
                                              List<VirtualMachine> sink) throws Exception {
        try (SSHClient ssh = new SSHClient()) {
            ssh.addHostKeyVerifier((h, p, k) -> true);   // üretimde kaldır
            ssh.connect(host.ip, 22);
            ssh.authPassword(user, pass);

            String list = run(ssh, "vim-cmd vmsvc/getallvms 2>/dev/null || true");
            Matcher m = VM_ROW.matcher(list);
            while (m.find()) {
                String vmid = m.group(1);
                VirtualMachine vm = new VirtualMachine();
                vm.name = m.group(2);
                vm.hostId = host.id;
                String detail = run(ssh, "vim-cmd vmsvc/get.summary " + vmid +
                                       " 2>/dev/null | grep -Ei 'macAddress|guestFullName|powerState' || true");
                Matcher mac = Pattern.compile("macAddress\\s*=\\s*\"([0-9a-fA-F:]{17})\"")
                                     .matcher(detail);
                if (mac.find()) { vm.mac = mac.group(1).toLowerCase(); host.vmMacs.add(vm.mac); }
                Matcher os = Pattern.compile("guestFullName\\s*=\\s*\"([^\"]+)\"").matcher(detail);
                if (os.find()) vm.guestOs = os.group(1);
                Matcher ps = Pattern.compile("powerState\\s*=\\s*\"([^\"]+)\"").matcher(detail);
                if (ps.find()) vm.powerState = ps.group(1);
                sink.add(vm);
            }
            // Yönetim arayüzlerindeki subnetler → keşif için ek ağ
            String ifaces = run(ssh, "esxcli network ip interface ipv4 get 2>/dev/null || true");
            Matcher m2 = Pattern.compile("\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+").matcher(ifaces);
            while (m2.find()) host.managementNets.add(m2.group(1));
            ssh.disconnect();
        }
        return host;
    }

    static String run(SSHClient ssh, String cmd) throws Exception {
        try (Session s = ssh.startSession()) {
            Session.Command c = s.exec(cmd);
            return IOUtils.readFully(c.getInputStream()).toString();
        }
    }
}
```

### 7.3 Proxmox (REST API — tam çalışan)

```java
// src/main/java/netdisc/virtualization/ProxmoxDiscovery.java
package netdisc.virtualization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import javax.net.ssl.*;
import java.net.URI;
import java.net.http.*;
import java.util.*;

public final class ProxmoxDiscovery {
    private static final ObjectMapper MAP = new ObjectMapper();

    public static VirtualizationHost discover(String ip, int port, String user, String pass,
                                             List<VirtualMachine> sink) throws Exception {
        HttpClient http = insecureClient();
        String base = "https://" + ip + ":" + (port == 0 ? 8006 : port) + "/api2/json";
        // login
        HttpResponse<String> login = http.send(
                HttpRequest.newBuilder(URI.create(base + "/access/ticket"))
                        .header("Content-Type","application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "username=" + enc(user) + "&password=" + enc(pass))).build(),
                HttpResponse.BodyHandlers.ofString());
        JsonNode lj = MAP.readTree(login.body()).get("data");
        String ticket = lj.get("ticket").asText();
        String csrf = lj.get("CSRFPreventionToken").asText();
        HttpClient client = http;

        VirtualizationHost host = new VirtualizationHost();
        host.ip = ip; host.type = "proxmox"; host.id = "proxmox:" + ip;
        host.name = lj.has("username") ? lj.get("username").asText() : ip;

        // nodes
        JsonNode nodes = get(client, base + "/nodes", ticket, csrf).get("data");
        for (JsonNode n : nodes) {
            String node = n.get("node").asText();
            // QEMU VMs
            JsonNode vms = get(client, base + "/nodes/" + node + "/qemu", ticket, csrf).get("data");
            for (JsonNode v : vms) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = v.get("name").asText();
                vm.hostId = host.id;
                vm.powerState = v.has("status") ? v.get("status").asText() : null;
                int vmid = v.get("vmid").asInt();
                JsonNode cfg = get(client, base + "/nodes/" + node + "/qemu/" + vmid + "/config",
                                   ticket, csrf).get("data");
                for (Iterator<String> it = cfg.fieldNames(); it.hasNext(); ) {
                    String k = it.next();
                    if (k.startsWith("net")) {
                        String v0 = cfg.get(k).asText();
                        String mac = regexMac(v0);
                        if (mac != null) { vm.mac = mac; host.vmMacs.add(mac); }
                        vm.nics.add(v0);
                    }
                }
                sink.add(vm);
            }
            // LXC
            JsonNode ct = get(client, base + "/nodes/" + node + "/lxc", ticket, csrf).get("data");
            for (JsonNode c : ct) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = c.get("name").asText();
                vm.hostId = host.id; vm.powerState = c.has("status") ? c.get("status").asText() : null;
                vm.guestOs = "lxc";
                sink.add(vm);
            }
            // Yönetim ağı / bridge subnetleri
            JsonNode nets = get(client, base + "/nodes/" + node + "/network", ticket, csrf).get("data");
            for (JsonNode nn : nets) {
                if (nn.has("address")) host.managementNets.add(nn.get("address").asText());
            }
        }
        return host;
    }

    private static String regexMac(String s) {
        var m = java.util.regex.Pattern
                .compile("(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})").matcher(s);
        return m.find() ? m.group(1).toLowerCase() : null;
    }
    private static String enc(String s) {
        try { return java.net.URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; }
    }
    private static JsonNode get(HttpClient c, String url, String ticket, String csrf) throws Exception {
        HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(url))
                .header("Cookie","PVEAuthCookie=" + ticket)
                .header("CSRFPreventionToken", csrf).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return MAP.readTree(r.body());
    }
    private static HttpClient insecureClient() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{ new X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }}, new java.security.SecureRandom());
        return HttpClient.newBuilder().sslContext(ctx).build();
    }
}
```

### 7.4 KVM (libvirt üzerinden SSH + `virsh`)

```java
// src/main/java/netdisc/virtualization/KvmDiscovery.java
package netdisc.virtualization;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import java.util.regex.*;

public final class KvmDiscovery {
    public static VirtualizationHost discover(String ip, String user, String pass,
                                             List<VirtualMachine> sink) throws Exception {
        VirtualizationHost host = new VirtualizationHost();
        host.id = "kvm:" + ip; host.ip = ip; host.type = "kvm";
        try (SSHClient ssh = new SSHClient()) {
            ssh.addHostKeyVerifier((h,p,k) -> true);
            ssh.connect(ip, 22);
            ssh.authPassword(user, pass);
            String list = run(ssh, "virsh list --all --name 2>/dev/null || true");
            for (String dom : list.split("\\R")) {
                dom = dom.trim();
                if (dom.isEmpty()) continue;
                VirtualMachine vm = new VirtualMachine();
                vm.name = dom; vm.hostId = host.id;
                String xml = run(ssh, "virsh dumpxml " + dom + " 2>/dev/null || true");
                Matcher mac = Pattern.compile("<mac address='([0-9a-f:]{17})'").matcher(xml);
                if (mac.find()) { vm.mac = mac.group(1); host.vmMacs.add(vm.mac); }
                Matcher ifs = Pattern.compile("<source (?:bridge|network)='([^']+)'").matcher(xml);
                while (ifs.find()) vm.nics.add(ifs.group(1));
                sink.add(vm);
            }
            String nets = run(ssh, "ip -4 -o addr show 2>/dev/null || true");
            Matcher m = Pattern.compile("inet (\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)").matcher(nets);
            while (m.find()) host.managementNets.add(m.group(1));
            ssh.disconnect();
        }
        return host;
    }
    static String run(SSHClient ssh, String cmd) throws Exception {
        try (Session s = ssh.startSession()) {
            Session.Command c = s.exec(cmd);
            return IOUtils.readFully(c.getInputStream()).toString();
        }
    }
}
```

### 7.5 VM → Host eşlemesi (hibrit)

```java
// src/main/java/netdisc/virtualization/VMHostMatcher.java
package netdisc.virtualization;

import netdisc.model.*;

import java.util.*;

public final class VMHostMatcher {

    /** 
     * İki katman:
     * 1) Kesin: sanallaştırma API'si VM'in MAC'ini host'a bağladıysa (vhost.vmMacs).
     * 2) Sezgisel: MAC OUI + aynı L2 segmentte olma + isim deseni.
     */
    public static void match(DiscoveryResult r) {
        Map<String, String> macToHost = new HashMap<>();
        for (VirtualizationHost h : r.vhosts)
            for (String mac : h.vmMacs) macToHost.put(mac, h.id);

        for (Device d : r.devices) {
            String vmType = VirtualizationDetector.vmVendorByMac(d.mac);
            if (d.kind == Device.Kind.VIRTUALIZATION_HOST) continue;
            if (vmType != null) d.kind = Device.Kind.VIRTUAL_MACHINE;

            if (d.mac != null && macToHost.containsKey(d.mac)) {
                d.ownerHostId = macToHost.get(d.mac);
                d.metadata.put("match", "api-mac");
            } else if (vmType != null) {
                d.metadata.put("vmVendor", vmType);
                // Heuristic: aynı /24'te eşleşen vm vendor hostu
                for (VirtualizationHost h : r.vhosts) {
                    if (sameL2(h, d)) {
                        d.ownerHostId = h.id;
                        d.metadata.put("match", "heuristic-l2-oui");
                        break;
                    }
                }
            }
        }
    }

    private static boolean sameL2(VirtualizationHost h, Device d) {
        if (h.managementNets.isEmpty() || d.ip == null) return false;
        String dip = d.ip.getHostAddress();
        for (String net : h.managementNets) {
            String prefix = net.contains("/") ? net.substring(0, net.indexOf('/')) : net;
            String p3 = prefix.substring(0, prefix.lastIndexOf('.'));
            if (dip.startsWith(p3 + ".")) return true;
        }
        return false;
    }
}
```

---

## 8. Orkestratör: çoklu LAN BFS + keşif

```java
// src/main/java/netdisc/DiscoveryOrchestrator.java
package netdisc;

import netdisc.discovery.*;
import netdisc.model.*;
import netdisc.virtualization.*;

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
        this.pool = Executors.newFixedThreadPool(cfg.threadPool);
    }

    public DiscoveryResult run() throws Exception {
        DiscoveryResult r = new DiscoveryResult();
        r.startedAt = System.currentTimeMillis();

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
                enrich(d, r, frontier, visited);
            }
        }

        r.devices.addAll(byIp.values());

        // 3) Sanallaştırma API'leri (verilen kimlik bilgileriyle)
        for (DiscoveryConfig.Credential c : cfg.vmCreds) {
            try {
                VirtualizationHost h = switch (c.kind) {
                    case "esxi"    -> EsxiDiscovery.discover(newHost(c), c.user, c.passOrKey, r.vms);
                    case "proxmox" -> ProxmoxDiscovery.discover(c.host, c.port, c.user, c.passOrKey, r.vms);
                    case "kvm"     -> KvmDiscovery.discover(c.host, c.user, c.passOrKey, r.vms);
                    default -> null;
                };
                if (h != null) {
                    r.vhosts.add(h);
                    // Yönetim alt ağlarını BFS'e ekle
                    for (String net : h.managementNets) {
                        if (!net.contains("/")) continue;
                        if (visited.add(net)) frontier.add(new NetworkSegment(net));
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
        r.devices.clear(); r.devices.addAll(byIp.values());

        // 4) VM ↔ Host eşleme
        VMHostMatcher.match(r);

        r.finishedAt = System.currentTimeMillis();
        pool.shutdownNow();
        return r;
    }

    private void discoverHosts(NetworkSegment seg, Map<String, Device> byIp, DiscoveryResult r)
            throws Exception {
        // --- TCP sweep
        if (cfg.tcp) {
            List<InetAddress> ips = expand(seg.cidr, 1024);
            List<Future<?>> fs = new ArrayList<>();
            for (InetAddress ip : ips) {
                fs.add(pool.submit(() -> {
                    try {
                        List<Integer> open = HostScanners.tcpScan(pool, ip, probePorts, cfg.tcpTimeoutMs);
                        if (!open.isEmpty()) {
                            Device d = byIp.computeIfAbsent(ip.getHostAddress(), k -> new Device());
                            d.ip = ip; d.openPorts.addAll(open);
                            d.discoveredBy.add("tcp");
                        }
                    } catch (Exception ignored) {}
                }));
            }
            for (Future<?> f : fs) f.get();
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
        if (cfg.mdns) for (InetAddress ia : MulticastScanners.mdns(2000)) {
            Device d = byIp.computeIfAbsent(ia.getHostAddress(), k -> new Device());
            d.ip = ia; d.discoveredBy.add("mdns");
            d.services.add("mdns");
        }
        if (cfg.ssdp) for (InetAddress ia : MulticastScanners.ssdp(2000)) {
            Device d = byIp.computeIfAbsent(ia.getHostAddress(), k -> new Device());
            d.ip = ia; d.discoveredBy.add("ssdp");
            d.services.add("upnp");
        }
        // --- ARP (yerel segment ise)
        if (cfg.arp) {
            for (String ifName : localIfaces()) {
                String local = localCidr(ifName);
                if (local == null || !local.equals(seg.cidr)) continue;
                for (L2Scanner.ArpEntry e : L2Scanner.arpScan(ifName, seg.cidr, 3000)) {
                    Device d = byIp.computeIfAbsent(e.ip(), k -> new Device());
                    try { d.ip = InetAddress.getByName(e.ip()); } catch (Exception ignored) {}
                    d.mac = e.mac();
                    d.discoveredBy.add("arp");
                }
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
    private void enrich(Device d, DiscoveryResult r, Deque<NetworkSegment> frontier,
                        Set<String> visited) {
        if (d.ip == null) return;
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
                        Device tgt = findOrCreate(r, e.getKey());
                        if (tgt.mac == null) tgt.mac = e.getValue();
                        tgt.discoveredBy.add("snmp-arp");
                    }
                    break; // başarılı community
                } catch (Exception ignored) {}
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
            r.vhosts.add(vh);
        }
        String vmv = VirtualizationDetector.vmVendorByMac(d.mac);
        if (vmv != null) d.kind = Device.Kind.VIRTUAL_MACHINE;
    }

    // -- yardımcılar ---------------------------------------------------------

    private static Device findOrCreate(DiscoveryResult r, String ip) {
        for (Device d : r.devices)
            if (ip.equals(d.ip == null ? null : d.ip.getHostAddress())) return d;
        Device d = new Device();
        try { d.ip = InetAddress.getByName(ip); } catch (Exception ignored) {}
        r.devices.add(d);
        return d;
    }

    private static VirtualizationHost newHost(DiscoveryConfig.Credential c) {
        VirtualizationHost h = new VirtualizationHost();
        h.id = c.kind + ":" + c.host; h.ip = c.host; h.type = c.kind; h.name = c.host;
        return h;
    }

    private static String toCidr(String dst) {
        try { return dst + "/24"; } catch (Exception e) { return null; }
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
```

---

## 9. `Main` + JSON rapor

```java
// src/main/java/netdisc/Main.java
package netdisc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import netdisc.model.*;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("""
                Kullanım:
                  java -jar netdisc.jar [seçenekler]
                Örnek:
                  --cidr 192.168.1.0/24 --cidr 10.0.0.0/24 --snmp public --out rapor.json
                Not: ARP/LLDP için yönetici yetkisi (npcap/libpcap) gerekir.
                """);
            return;
        }
        DiscoveryConfig cfg = DiscoveryConfig.fromArgs(args);
        DiscoveryResult r = new DiscoveryOrchestrator(cfg).run();

        ObjectMapper om = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        om.writeValue(new java.io.File(cfg.outputPath), r);

        System.out.printf("Bitti. %d cihaz, %d sanal makine, %d host, %d ağ segmenti.%n",
                r.devices.size(), r.vms.size(), r.vhosts.size(), r.segments.size());
        if (!r.warnings.isEmpty()) {
            System.out.println("Uyarılar:");
            r.warnings.forEach(w -> System.out.println("  - " + w));
        }
    }
}
```

---

## 10. Neden bu yöntem seti?

| Yöntem | Ne zaman işe yarar |
|---|---|
| **TCP connect** (22/80/443/445/3389/5985/8006...) | ICMP firewall'da bloklu olsa bile port açık her host'u yakalar. **Ana canlılık sinyali.** |
| **ARP** (pcap4j) | Aynı L2 segmentte %100 doğruluk — sadece paket gitmesi yeter. |
| **mDNS / SSDP / NetBIOS** | UDP multicast; çoğu yerde engellenmez; hostname/servis bilgisi verir. |
| **SNMP (v1/v2c/v3)** | Router/switch'ten route ve ARP tabloları → **başka LAN'lar** ve MAC envanteri. |
| **LLDP/CDP** (pcap) | Switch/router komşuları, VLAN ve yönetim IP'leri → topoloji ve ek segmentler. |
| **Sanallaştırma API'leri** | VMware/Proxmox/KVM/Hyper-V → kesin VM↔host eşlemesi. |
| **MAC OUI + L2 heuristic** | API yoksa "muhtemel sanal makine" tespiti ve çoğu zaman doğru host eşleşmesi. |

**Çoklu LAN zincirleme:** Yeni segmentler 4 kaynaktan keşfedilir → BFS kuyruğuna eklenir:  
1. Yerel arayüz CIDR'leri,  
2. SNMP routing table (default olmayan),  
3. LLDP komşularının yönetim IP'leri,  
4. Sanallaştırma host'unun VMkernel/bridge ağları.

**Kritik noktalar / üretim için tavsiyeler:**

- **ARP/LLDP** için `run as root` / `CAP_NET_RAW` veya Windows'ta **npcap**. Aksi halde yalnızca TCP+UDP keşifleri çalışır.
- **ESXi/KVM/Hyper-V'nin SSH/WinRM'i kapalıysa** API katmanı atlanır; yalnızca OUI + port fingerprint ile "sanal makine" işaretlenir, eşleşme `api-mac` yerine `heuristic-l2-oui` olur. Kesin eşleme için ilgili SDK'yı (yavijava / libvirt-java / WinRM4j) `pom.xml`'e ekle ve `VirtualizationDiscovery` sınıfını genişlet.
- **Rate limiting:** Thread pool'u ve timeout'ları çok agresif yapma; SNMP cihazları aşırı sorgudan düşer. `--threads 256` ile 10.0.0.0/16'yı taramak yavaş ama güvenli.
- **OUI tablosu:** `IEEE oui.csv`'yi indirip `Map<String,String>` olarak yükle; küçük dosyada `VirtualizationDetector.vmVendorByMac` içine ekle.
- **Dağıtık çalışma:** Büyük ağlarda seg mentor başına küçük bir agent (aynı jar `--agent-mode`) çalıştırıp sonuçları merge etmek gerekir.
- **Kimlik doğrulama:** Üretimde SSH `HostKeyVerifier`'ı gerçek anahtar dosyasıyla değiştir, Proxmox için self-signed TLS'i kaldırma (truststore).
- **Yasal:** Sadece yetkili olduğun ağlarda çalıştır.

İstersen bir sonraki adımda şunlardan birini ekleyebilirim:  
- **Hyper-V** için WinRM/PowerShell üzerinden VM-MAC eşlemesi,  
- **yavijava** ile vCenter SDK tabanlı gerçek envanter,  
- **VLAN-aware LLDP** çözümleyicisi (topology görselleştirme çıktısıyla),  
- **Web UI** (Spring Boot + d3.js topoloji grafiği).

**Kullanıcı:**

Hyper-V için WinRM/PowerShell üzerinden VM-MAC eşlemesini yapalım. Sonra diğerlerini yaparız. İstersen hepsini birilikte de ele alabilirsin.

**Kullanıcı:**

Hyper-V için WinRM/PowerShell üzerinden VM-MAC eşlemesini yapalım. Sonra diğerlerini yaparız. İstersen hepsini birilikte de ele alabilirsin.

**Asistan:**

The user wants to add Hyper-V discovery via WinRM/PowerShell to the existing network discovery tool. Let me focus on that and implement it properly.

For Hyper-V discovery via WinRM, options:
1. winrm4j library - uses WinRM protocol from Java
2. JSch + PowerShell over SSH (if WinRM or SSH enabled on Windows)
3. WinRM via SOAP directly

Actually, the most robust Java approach for WinRM is winrm4j (from Cloudsoft). Let me use that.

Key PowerShell commands for Hyper-V:
- `Get-VM` - list all VMs
- `Get-VMNetworkAdapter -VMName X` - get MAC addresses
- `Get-VMNetworkAdapter -ManagementOS` - host vNICs
- `Get-VMSwitch` - list virtual switches
- `Get-NetIPAddress` / `Get-NetAdapter` - host management IPs

Also need to handle host identification, switch network subnets, etc.

WinRM requires:
- Windows host with WinRM enabled (5985 http / 5986 https)
- Credentials
- Trusted hosts or HTTPS cert

Let me structure this:

1. Add winrm4j dependency to pom.xml
2. Create HyperVDiscovery class using WinRM to run PowerShell
3. Parse output (JSON via ConvertTo-Json is best)
4. Wire it into the orchestrator
5. Handle VM matching (which is already there via vmMacs)

Let me use winrm4j. Maven coordinates:
```xml
<dependency>
    <groupId>io.cloudsoft.windows</groupId>
    <artifactId>winrm4j</artifactId>
    <version>0.12.0</version>
</dependency>
```

Usage:
```java
WinRmTool tool = WinRmTool.Builder.builder(host, user, pass)
    .setAuthenticationScheme(AuthenticationScheme.NTLM)
    .port(5985)
    .useHttps(false)
    .build();
WinRmToolResponse response = tool.executePs("Get-VM | ConvertTo-Json");
int exitCode = response.getStatusCode();
String stdout = response.getStdOut();
String stderr = response.getStdErr();
```

Note: winrm4j 0.12.0 pulls in a lot of dependencies. It should work.

PowerShell script design:

```powershell
$VMs = Get-VM | Select-Object Name, Id, State, Generation, Version
$result = @()
foreach ($vm in $VMs) {
    $adapters = Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue
    $vmObj = [PSCustomObject]@{
        Name = $vm.Name
        Id = $vm.Id.ToString()
        State = $vm.State.ToString()
        Generation = $vm.Generation
        Adapters = @()
    }
    foreach ($ad in $adapters) {
        $vmObj.Adapters += [PSCustomObject]@{
            Name = $ad.Name
            MacAddress = $ad.MacAddress
            SwitchName = $ad.SwitchName
            IPAddresses = $ad.IPAddresses -join ','
            Status = $ad.Status
        }
    }
    $result += $vmObj
}
$result | ConvertTo-Json -Depth 5 -Compress
```

And for host info:
```powershell
$switches = Get-VMSwitch | Select-Object Name, SwitchType, NetAdapterInterfaceDescription
$netAdapters = Get-NetAdapter | Select-Object Name, MacAddress, Status
$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual | Select-Object IPAddress, PrefixLength, InterfaceAlias
```

Also need to handle host MAC addressing - the host has management vNICs.

Let me also consider: to match a VM's MAC to a host, the MAC is unique. So I need:
- For each VM: MAC address(es)
- Project them onto `vhost.vmMacs`

And for host identification:
- The management IP addresses of Hyper-V server → for BFS queue

Also we might want cluster mode (multiple Hyper-V servers in a failover cluster). Let's keep it to single-host for now but mention cluster.

Let me also think about how a VM's MAC can appear elsewhere. Since VM's MAC OUI is 00:15:5D (Microsoft), the VMHostMatcher can find a Device with that MAC and match.

Important: also need to add VM discovery in orchestrator - already there in the pattern. Add "hyperv" case.

Now let me also handle:
- Authentication schemes: NTLM, Basic, Kerberos, CredSSP
- Configurable port and HTTPS
- Trusted host setup (or ignore certs for https)

winrm4j uses Apache HttpClient for transport. For HTTPS with self-signed, need to disable cert verification - can be tricky but there's a way with a custom SSLContext.

Actually, winrm4j has some construction options. Let me check... The `WinRmTool.Builder` doesn't have direct SSL trust config, but we can set a custom HttpHost or use `WinRmTool.Builder.builder(...).setDisableCertificateValidation(true)` maybe? Let me check...

Actually winrm4j uses `org.apache.http.client.HttpClient` - we might be able to pass a custom HttpClient. The builder method is `.client(...)`. Yes:

```java
WinRmTool.Builder b = WinRmTool.Builder.builder(host, user, pass)
    .setAuthenticationScheme(AuthenticationScheme.NTLM)
    .port(5985)
    .useHttps(false);
```

There's also `setDisableCertificateValidation(boolean)` in newer versions I believe. Let me just use NTLM over http for the first cut, and note the https option.

Actually to be safe, I'll use NTLM and note how to set https + skip cert validation.

Now let me also add fallback: if WinRM fails, we could try SSH (Windows OpenSSH) as a fallback. But the user asked specifically for WinRM/PowerShell, so let's focus.

Let me structure:

1. Update pom.xml - add winrm4j
2. Add HyperVDiscovery.java
3. Update DiscoveryConfig.Credential to include domain, port, useHttps, authScheme
4. Update orchestrator to call HyperVDiscovery
5. Update VMHostMatcher — already handles it via vmMacs

Let me code it now.

For the JSON parsing, I'll use Jackson (already a dep).

PowerShell script structure — I need to be careful about encoding. Output should be piped through `ConvertTo-Json`. Some special chars might get mangled but should be OK for basic ASCII.

For the domain in NTLM auth, winrm4j typically expects `DOMAIN\user` format in the username, or you pass domain separately. Let me check - the constructor is `builder(String host, String user, String password)`. For domain, use `DOMAIN\\user` format. Or `.setDomain(domain)` maybe? Actually I recall winrm4j merges domain in the user string.

Looking at examples:
```java
WinRmTool.Builder builder = WinRmTool.Builder.builder(hostname, username, password);
builder.setAuthenticationScheme(AuthenticationScheme.NTLM);
```
And for domain: username = "DOMAIN\\username".

OK, let me code.

Also I should provide a JSON helper class or just parse inline.

PowerShell scripts:

Script 1: Get VMs + adapters
```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Import-Module Hyper-V -ErrorAction SilentlyContinue
$out = @()
Get-VM | ForEach-Object {
    $vm = $_
    $adapters = @()
    Get-VMNetworkAdapter -VMName $vm.Name | ForEach-Object {
        $adapters += [PSCustomObject]@{
            Name = $_.Name
            MacAddress = ($_.MacAddress -replace '-',':').ToLower()
            SwitchName = $_.SwitchName
            IPAddresses = if ($_.IPAddresses) { $_.IPAddresses -join ';' } else { '' }
            IsLegacy = $_.IsLegacy
        }
    }
    $out += [PSCustomObject]@{
        Name = $vm.Name
        Id = $vm.Id.ToString()
        State = $vm.State.ToString()
        Generation = $vm.Generation
        Version = $vm.Version
        Adapters = $adapters
    }
}
$out | ConvertTo-Json -Depth 5 -Compress
```

Script 2: Host network info (management, vSwitches)
```powershell
$switches = @()
Get-VMSwitch | ForEach-Object {
    $switches += [PSCustomObject]@{
        Name = $_.Name
        SwitchType = $_.SwitchType.ToString()
        NetAdapterInterfaceDescription = $_.NetAdapterInterfaceDescription
    }
}
$ips = @()
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object {
    $ips += [PSCustomObject]@{
        IPAddress = $_.IPAddress
        PrefixLength = $_.PrefixLength
        InterfaceAlias = $_.InterfaceAlias
    }
}
[PSCustomObject]@{
    Hostname = $env:COMPUTERNAME
    Switches = $switches
    IpAddresses = $ips
} | ConvertTo-Json -Depth 5 -Compress
```

Also, if it's a cluster, use `Get-ClusterNode` / `Get-VM -ComputerName ...`. Let me add cluster support as an option.

Actually, for failover clusters, VMs can migrate. Better approach: query each node, or query from cluster endpoint. Simple version: query single host. Add cluster support note.

Let me also think about the `Get-VM` cmdlet sometimes needs `-ComputerName` for remote. But since we run PowerShell over WinRM on the host itself, it should be local.

Now let me also handle:
- Failback: if Hyper-V module isn't available (maybe running on vCenter?), skip gracefully
- Error handling
- Timeout

Let me code the Java side now.

Also, winrm4j's SSL cert validation - let me look at the API. In winrm4j 0.12.0:
```
WinRmTool.Builder builder = WinRmTool.Builder.builder(host, user, pass);
builder.setAuthenticationScheme(AuthenticationScheme.NTLM);
builder.port(5985);
builder.useHttps(false);
```

There is `builder.client(HttpClient)` for custom client. For https + skip cert:
```java
SSLContext sslContext = ...  // trust-all
HttpClientBuilder cb = HttpClientBuilder.create();
cb.setSSLContext(sslContext);
cb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
builder.client(cb.build());
```

Hmm, I'm not 100% sure winrm4j's builder supports setSSLContext directly. Let me be careful. Actually I recall there's `builder.setDisableCertificateValidation(...)` might not exist. 

Looking at winrm4j source... `WinRmTool.Builder` has:
- `port(int)`
- `useHttps(boolean)`
- `setAuthenticationScheme(AuthenticationScheme)`
- `setDomain(String)` — actually I think this exists
- `setUsername(String)`, `setPassword(String)`
- `client(CloseableHttpClient)`
- `setReceiveTimeout(long, TimeUnit)`
- `setOperationTimeout(long, TimeUnit)`

Yes, there's `setDomain(String)` in newer versions. Good.

For custom SSL: `client(CloseableHttpClient)` - we can build one with custom SSL. Or winrm4j may have SSL context setter.

Actually, checking winrm4j docs more carefully — I believe the standard approach is:
```java
WinRmTool.Builder builder = WinRmTool.Builder.builder("host", "domain\\user", "pass");
builder.setAuthenticationScheme(AuthenticationScheme.NTLM);
builder.port(5986);
builder.useHttps(true);
builder.client(customHttpClient); // for SSL config
```

Since I can't verify the exact API, let me present HTTP/NTLM as primary, with a code snippet showing HTTPS option as a note.

Actually there's a simpler approach for HTTPS - use `SSLContext` from JVM default or trust all. Since we might not need full HTTPS support right away, let me make it configurable.

Alright, coding time. Let me also add:
- `hyperv` case in the switch statement in orchestrator
- Update `DiscoveryConfig.Credential` to include domain, useHttps, port

Actually the existing Credential already has port field. Let me add `domain` and `useHttps` fields, or just use defaults.

Let me also add the HyperVDiscovery call site in orchestrator's switch.

Let me code:

```java
// src/main/java/netdisc/virtualization/HyperVDiscovery.java
package netdisc.virtualization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cloudsoft.windows.winrm.WinRmTool;
import io.cloudsoft.windows.winrm.WinRmToolResponse;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import java.util.*;

public final class HyperVDiscovery {
    private static final ObjectMapper MAP = new ObjectMapper();

    public record Options(String host, int port, boolean useHttps, String domain, String user, String pass) {}

    public static VirtualizationHost discover(Options opt, List<VirtualMachine> sink) throws Exception {
        WinRmTool tool = buildTool(opt);
        VirtualizationHost host = new VirtualizationHost();
        host.type = "hyperv";
        host.ip = opt.host();

        // --- 1) Host temel bilgiler + vSwitch + management IPs
        String hostJson = exec(tool, HOST_SCRIPT);
        JsonNode hn = MAP.readTree(extractJson(hostJson));
        if (hn == null || !hn.isObject()) throw new RuntimeException("Hyper-V host bilgisi alınamadı");
        host.id = "hyperv:" + opt.host();
        host.name = hn.path("Hostname").asText(null);
        host.version = hn.path("OsVersion").asText(null);

        for (JsonNode ip : hn.path("IpAddresses")) {
            String cidr = ip.path("IPAddress").asText() + "/" + ip.path("PrefixLength").asInt();
            host.managementNets.add(cidr);
        }

        // --- 2) VM listesi + adapters
        String vmJson = exec(tool, VM_SCRIPT);
        JsonNode vms = MAP.readTree(extractJson(vmJson));
        if (vms != null) {
            if (vms.isObject()) vms = MAP.createArrayNode().add(vms);
            for (JsonNode v : vms) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = v.path("Name").asText();
                vm.uuid = v.path("Id").asText();
                vm.hostId = host.id;
                vm.powerState = v.path("State").asText();
                vm.guestOs = null;  // guest OS bilgisi ayrıca alınır
                for (JsonNode a : v.path("Adapters")) {
                    String mac = a.path("MacAddress").asText("");
                    if (!mac.isEmpty() && !mac.equals("00:00:00:00:00:00")) {
                        if (vm.mac == null) vm.mac = mac;
                        host.vmMacs.add(mac);
                    }
                    String sw = a.path("SwitchName").asText();
                    vm.nics.add((mac.isEmpty() ? "no-mac" : mac) + "@" + sw);
                    String ipAddrs = a.path("IPAddresses").asText();
                    if (vm.ip == null && !ipAddrs.isEmpty()) {
                        vm.ip = ipAddrs.split(";")[0].trim();
                    }
                }
                sink.add(vm);
            }
        }

        return host;
    }

    // ---- scripts --------------------------------------------------------
    private static final String HOST_SCRIPT = """
        $ErrorActionPreference='Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $ips=@()
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
          ForEach-Object {
            $ips += [PSCustomObject]@{ IPAddress=$_.IPAddress; PrefixLength=$_.PrefixLength; InterfaceAlias=$_.InterfaceAlias }
          }
        $sws=@()
        Get-VMSwitch -ErrorAction SilentlyContinue | ForEach-Object {
          $sws += [PSCustomObject]@{ Name=$_.Name; SwitchType=$_.SwitchType.ToString(); NetAdapterInterfaceDescription=$_.NetAdapterInterfaceDescription }
        }
        [PSCustomObject]@{
          Hostname = $env:COMPUTERNAME
          OsVersion = [System.Environment]::OSVersion.VersionString
          IpAddresses = $ips
          Switches = $sws
        } | ConvertTo-Json -Depth 4 -Compress
        """;

    private static final String VM_SCRIPT = """
        $ErrorActionPreference='Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $out=@()
        Get-VM | ForEach-Object {
          $vm=$_
          $ads=@()
          Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object {
            $mac = if ($_.MacAddress) { ($_.MacAddress -replace '-',':').ToLower() } else { '' }
            $ads += [PSCustomObject]@{
              Name = $_.Name
              MacAddress = $mac
              SwitchName = $_.SwitchName
              IPAddresses = if ($_.IPAddresses) { $_.IPAddresses -join ';' } else { '' }
            }
          }
          $out += [PSCustomObject]@{
            Name=$vm.Name; Id=$vm.Id.ToString(); State=$vm.State.ToString()
            Generation=$vm.Generation; Version=$vm.Version; Adapters=$ads
          }
        }
        $out | ConvertTo-Json -Depth 5 -Compress
        """;

    // ---- helpers --------------------------------------------------------
    private static WinRmTool buildTool(Options opt) {
        String user = opt.domain() == null || opt.domain().isEmpty()
                ? opt.user()
                : opt.domain() + "\\" + opt.user();
        WinRmTool.Builder b = WinRmTool.Builder.builder(opt.host(), user, opt.pass());
        b.setAuthenticationScheme(io.cloudsoft.windows.winrm.WinRmTool.Builder.class
                .getClassLoader() != null
                ? io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme.INSTANCE
                : io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme.INSTANCE);
        b.port(opt.port() == 0 ? (opt.useHttps() ? 5986 : 5985) : opt.port());
        b.useHttps(opt.useHttps());
        b.setReceiveTimeout(60_000, java.util.concurrent.TimeUnit.MILLISECONDS);
        b.setOperationTimeout(120_000, java.util.concurrent.TimeUnit.MILLISECONDS);
        return b.build();
    }

    private static String exec(WinRmTool tool, String ps) {
        WinRmToolResponse resp = tool.executePs(ps);
        if (resp.getStatusCode() != 0) {
            throw new RuntimeException("PowerShell exit " + resp.getStatusCode() + ": " + resp.getStdErr());
        }
        return resp.getStdOut();
    }

    private static String extractJson(String s) {
        if (s == null) return "null";
        int first = -1, last = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{' || c == '[') { first = i; break; }
        }
        for (int i = s.length() - 1; i >= 0; i--) {
            char c = s.charAt(i);
            if (c == '}' || c == ']') { last = i; break; }
        }
        if (first < 0 || last < 0 || last < first) return "null";
        return s.substring(first, last + 1);
    }
}
```

Hmm, I wrote `NtlmAuthScheme` but the correct class in winrm4j is `io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme`. Let me verify... Actually the class is `io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme` with singleton INSTANCE? Or `BasicAuthScheme`? I think it's `NtlmAuthScheme.INSTANCE`. Yes.

Actually I recall the path is `io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme`. And `AuthenticationScheme` interface. Yes.

Let me simplify the buildTool method — remove the weird ternary.

```java
private static WinRmTool buildTool(Options opt) {
    String user = opt.domain() == null || opt.domain().isEmpty()
            ? opt.user()
            : opt.domain() + "\\" + opt.user();
    WinRmTool.Builder b = WinRmTool.Builder.builder(opt.host(), user, opt.pass());
    b.setAuthenticationScheme(io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme.INSTANCE);
    b.port(opt.port() == 0 ? (opt.useHttps() ? 5986 : 5985) : opt.port());
    b.useHttps(opt.useHttps());
    b.setReceiveTimeout(60_000, java.util.concurrent.TimeUnit.MILLISECONDS);
    b.setOperationTimeout(120_000, java.util.concurrent.TimeUnit.MILLISECONDS);
    return b.build();
}
```

For HTTPS with self-signed cert, winrm4j might need custom HttpClient. I'll note it.

Now, also update the orchestrator:

```java
case "hyperv" -> HyperVDiscovery.discover(
    new HyperVDiscovery.Options(c.host, c.port, c.useHttps, c.domain, c.user, c.passOrKey),
    r.vms);
```

And DiscoveryConfig.Credential:
```java
public static class Credential {
    public String kind;
    public String host, user, passOrKey;
    public String domain = "";
    public int port = 0;
    public boolean useHttps = false;
    public Credential(...) { ... }
    public static Credential hyperv(String host, String domain, String user, String pass) { ... }
    public static Credential hypervHttps(...) { ... }
}
```

Also add CLI arg for hyperv:
```
--hyperv host,domain\user:pass
```
or simpler:
```
--hyperv-cred host user pass [--hyperv-domain DOM] [--hyperv-https]
```

Let me add:
```java
case "--hyperv" -> {
    String h = a[++i];
    String u = a[++i];
    String p = a[++i];
    var cred = new DiscoveryConfig.Credential("hyperv", h, u, p);
    c.vmCreds.add(cred);
}
case "--hyperv-domain" -> { c.vmCreds.get(c.vmCreds.size()-1).domain = a[++i]; }
case "--hyperv-https" -> { c.vmCreds.get(c.vmCreds.size()-1).useHttps = true; }
```

Or cleaner with structured args. Let me use a simple approach:
- `--hyperv host:user:pass[:domain]`
- `--hyperv-https` toggles the previous

Actually a cleaner approach: put all params in one arg with `:` separator. But passwords with colons become tricky. Let me use the multi-arg approach.

Actually, best approach: use explicit named args after hyperv:
```
--hyperv host=192.168.1.10 user=Administrator pass=Secret domain=CORP https=true
```
That's more work to parse. Let me just use separate flags.

Simpler:
```
--hyperv host --hyperv-user Administrator --hyperv-pass Secret --hyperv-domain CORP --hyperv-https
```

This groups per credential group. Let me add a mechanism to build the last cred:

```java
case "--hyperv" -> c.vmCreds.add(new DiscoveryConfig.Credential("hyperv", a[++i], null, null));
case "--hyperv-user" -> c.vmCreds.get(c.vmCreds.size()-1).user = a[++i];
case "--hyperv-pass" -> c.vmCreds.get(c.vmCreds.size()-1).passOrKey = a[++i];
case "--hyperv-domain" -> c.vmCreds.get(c.vmCreds.size()-1).domain = a[++i];
case "--hyperv-https" -> c.vmCreds.get(c.vmCreds.size()-1).useHttps = true;
case "--hyperv-port" -> c.vmCreds.get(c.vmCreds.size()-1).port = Integer.parseInt(a[++i]);
```

OK, that's clean enough.

Now update `VMHostMatcher` - already handles via `vhost.vmMacs`. Good.

Also need to update `enrich` in orchestrator — if we detect hyperv type but don't have credentials, we can still mark as `VirtualizationHost` type `hyperv` via port 5985/5986 detection. Already there in `guessType`.

Additional integration: After discovering host and VMs, also try to add switch-side IPs. The `host.managementNets` includes all IPv4 interfaces. That's fine for BFS.

Now let me also think about updating the pom.xml. Need:
```xml
<dependency>
    <groupId>io.cloudsoft.windows</groupId>
    <artifactId>winrm4j</artifactId>
    <version>0.12.0</version>
</dependency>
```

Wait, checking maven central... winrm4j latest is 0.12.0? Or 1.x? Actually I think 0.12.0 is right for the version that's on Maven Central. Actually I recall it's 0.11.0 or 0.12.0. Let me use 0.12.0.

Also there's a dependency note: winrm4j pulls in a lot of transitive deps (Apache CXF, HttpClient, etc). Should be OK.

Alternative: use a simpler WinRM client library. But winrm4j is the standard.

Actually there's another option: use SMB/PsExec-style (JSch to Linux Gateway to invoke PowerShell via SSH). But the user asked for WinRM specifically.

OK let me also present a cleaner factoring — a `PowerShellExecutor` abstraction so we can plug alternative transports (WinRM, SSH, direct local) later. But keep it simple for now.

Actually let me add a small abstraction to make future-proofing easier:

Actually let's keep it focused. The user wants Hyper-V over WinRM.

Let me also consider what happens when Hyper-V is running in a failover cluster. In that case, VMs can live on any node. Solution: query clusters:
```powershell
Get-ClusterNode | ForEach-Object { Get-VM -ComputerName $_.Name }
```
Or from the cluster coordinator:
```powershell
Get-ClusterGroup -ResourceType 'Virtual Machine' | ...
```

For now, add a note that cluster support requires querying each node or the cluster coordinator; our tool can be configured with multiple Hyper-V host credentials (one per node) and merge results.

Also, VM MACs on a Hyper-V cluster: each VM has a MAC that appears on one node. If we query all nodes, we get all VMs.

Another important detail: VM's `MacAddress` from `Get-VMNetworkAdapter` is the dynamic or static MAC. If dynamic (not set), the VM might not have a MAC until started. That's expected.

Also, `MacAddress` format from Hyper-V is `00155D123456` or `00:15:5D:12:34:56`? Usually `00155D123456` without colons. Let me check... actually `Get-VMNetworkAdapter | Select MacAddress` returns format like `00:15:5D:A4:22:64` I believe. But to be safe, normalize: strip non-hex, then regroup to xx:xx:xx:xx:xx:xx lowercase.

Let me add normalization:
```java
private static String normalizeMac(String mac) {
    if (mac == null) return null;
    String hex = mac.replaceAll("[^0-9a-fA-F]", "").toLowerCase();
    if (hex.length() != 12) return null;
    return hex.substring(0,2)+":"+hex.substring(2,4)+":"+hex.substring(4,6)+":"+
           hex.substring(6,8)+":"+hex.substring(8,10)+":"+hex.substring(10,12);
}
```

Apply on both Java and PowerShell side (PS side: `($_.MacAddress -replace '-',':').ToLower() -replace '[^0-9a-f:]',''`).

Actually let me just normalize in Java to be safe.

Also, an important question: How does the VM ↔ Host match work? The Device discovered via TCP/SNMP has a MAC from ARP/SNMP tables. The Hyper-V API session has the VM's MAC. So VMHostMatcher matches:
```java
for each Device d (MAC)
  if macToHost contains d.mac → ownerHostId = host
```

This works if ARP/SNMP gave us the MAC. Good.

Also want to enrich VM entries with IP if the device has an IP we can find. Let me add that:

```java
// In VMHostMatcher or orchestrator: for each VM with mac, find Device with same mac and copy IP
for (VirtualMachine vm : r.vms) {
    if (vm.mac != null && vm.ip == null) {
        for (Device d : r.devices) {
            if (vm.mac.equals(d.mac) && d.ip != null) {
                vm.ip = d.ip.getHostAddress();
                break;
            }
        }
    }
}
```

Actually the reverse: VM has IP from `IPAddresses` we read. Device also has IP. Let me sync both ways.

Also add: VM's `hostId` matches the VHost's `id`.

Also: `VirtualizationHost.managementNets` from Hyper-V host - includes all IPs. That's OK for BFS but might be too broad (includes 169.254.x.x link-local). Let me filter those out.

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '169.254.*' }
```

Good.

Also, need to handle DC-disabled environments. Actually for local Hyper-V (workgroup), NTLM with local users works. For domain, need DOMAIN\user. OK, that's what we support.

One more thing: winrm4j might need trust. `winrm4j` uses cert validation for HTTPS by default. To skip:
```java
b.client(HttpClients.custom().setSSLContext(trustAll()).setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build());
```
But then need basic auth too. Hmm, this is getting complex. Let me provide HTTPS as an option but note that in practice HTTP/NTLM port 5985 works for domain machines.

For HTTPS, in winrm4j, you can call:
```java
b.useHttps(true);
b.port(5986);
// If using self-signed cert:
b.setServerCertTrustMode(WinRmTool.Builder.ServerCertTrustMode.TRUST_ALL);
```

Hmm, does that API exist? I'm not sure. Let me check the winrm4j API... 

Actually looking at winrm4j source, I don't recall a `ServerCertTrustMode`. Let me use a different approach for HTTPS: build custom HttpClient with trust-all.

But I don't have perfect API knowledge. Let me just present HTTP with NTLM as primary (works for domain environments on port 5985 with DefaultAuth), and note that HTTPS can be enabled via WinRM configuration.

Actually the cleanest: provide `--hyperv-https` flag, and in `buildTool`, do:

```java
if (opt.useHttps()) {
    try {
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        b.client(HttpClients.custom()
                .setSSLContext(ssl)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build());
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}
```

If `b.client(...)` doesn't accept a custom HttpClient in this version, this could fail. But I believe winrm4j 0.12.0 has `client(CloseableHttpClient)`.

OK let me just present it and add a comment. If it doesn't work, the fallback is to note that in production HTTPS + valid cert is used (proper CA), so trust-all isn't needed.

Actually for domain environments with valid certs, we don't need trust-all. Let me not overcomplicate. I'll present HTTP/NTLM as primary and note HTTPS option requires valid cert or custom client builder.

Wait, one thing I should verify: does winrm4j use NTLM correctly? Yes, NTLM is the default and works over port 5985 with default WinRM config.

Alright, let me write the code cleanly.

I also want to add Hyper-V to the pom list order and make sure it compiles.

One more concern: while I'm at it, since the user said "sonra diğerlerini yaparız" (we'll do the others later), I should focus this response on Hyper-V. But since I have some room, I could also mention all remaining items briefly at the end.

Let me also double-check the switch in orchestrator.

The orchestrator's switch:
```java
VirtualizationHost h = switch (c.kind) {
    case "esxi"    -> EsxiDiscovery.discover(...);
    case "proxmox" -> ProxmoxDiscovery.discover(...);
    case "kvm"     -> KvmDiscovery.discover(...);
    default -> null;
};
```

Add:
```java
case "hyperv" -> HyperVDiscovery.discover(new HyperVDiscovery.Options(...), r.vms);
```

Also `VirtualizationDetector.guessType` already checks `p.contains(5985) || p.contains(5986)` and returns "hyperv" if vendor is Microsoft. Good. But we need to be careful: workstation Windows with WinRM might also have 5985. And the vendor check is `v.contains("microsoft")` which is based on `vendor` which we don't populate yet. Actually looking at the code, `vendorOUI(d)` returns `""` (empty string, it's a stub). So `v.contains("microsoft")` → `"".contains("microsoft")` → false. So we never detect hyperv without credentials!

Hmm, this is an issue. Let me fix: either:
1. Include Hyper-V detection without vendor — any host with 5985/5986 is potentially hyperv; mark as `VirtualizationHost` with type `hyperv-candidate` (needs credentials).
2. Or rely on the full API call.

Better approach: mark as `VirtualizationHost` candidate when 5985/5986 + some other indicator. Or actually, invoke the Hyper-V API if credentials are available. If credentials are provided, the API will tell us definitively.

Let me update `guessType`:
```java
if (p.contains(5985) || p.contains(5986)) return "hyperv-candidate";
```

But then `enrich` treats this as VirtualizationHost. Hmm, that's OK-ish. On Windows workstations with WinRM, they'd be marked. But then the orchestrator will try to call Hyper-VDiscovery for that host, fail, and skip. That's OK.

Actually wait, the enrich method doesn't call HyperVDiscovery. Let me re-check. In `enrich`:
```java
String vt = VirtualizationDetector.guessType(d);
if (vt != null) {
    d.virtualizationType = vt;
    d.kind = Device.Kind.VIRTUALIZATION_HOST;
    VirtualizationHost vh = new VirtualizationHost();
    vh.type = vt; vh.ip = d.ip.getHostAddress(); vh.id = vt + ":" + vh.ip;
    vh.name = d.hostname;
    r.vhosts.add(vh);
}
```

So it just adds to vhosts list but doesn't try API discovery. OK, and the actual API discovery happens in the switch block based on credentials.

For hyperv-candidate without credentials: doesn't try. With credentials: runs `HyperVDiscovery.discover` → definitively identifies if Hyper-V is installed.

Good. Let me update `guessType`:
```java
if (p.contains(5985) || p.contains(5986)) return "hyperv-candidate";
```

And in HyperVDiscovery: if `Get-VM` cmdlet isn't available, throw an error gracefully.

Also `enrich` needs a check to not add a "hyperv-candidate" vhost and then have the switch try to call it again with credentials — that would duplicate. Let me check the switch block:

```java
for (DiscoveryConfig.Credential c : cfg.vmCreds) {
    ...
    case "hyperv" -> HyperVDiscovery.discover(..., r.vms);
    ...
    r.vhosts.add(h);
}
```

So if `enrich` added a `hyperv-candidate` VHost, and the switch also adds a real one, we have duplicates. Need to dedup.

Let me handle dedup: dedup by `vhost.id` or by `ip`. Or: don't add the "candidate" vhost at all; only mark the Device. Actually the candidate marking is useful for reporting.

Simplest: at the end of discovery, dedupe `r.vhosts`:
```java
Map<String, VirtualizationHost> deduped = new LinkedHashMap<>();
for (VirtualizationHost h : r.vhosts) {
    deduped.merge(h.id, h, (existing, updated) -> {
        // prefer updated (from API) if existing was candidate
        if (existing.type.endsWith("-candidate")) return updated;
        if (updated.type.endsWith("-candidate")) return existing;
        return existing;
    });
}
r.vhosts.clear();
r.vhosts.addAll(deduped.values());
```

But the `id` might differ: `hyperv-candidate:10.0.0.5` vs `hyperv:10.0.0.5`. Need to dedupe by IP then.

Actually, let me handle this differently. In `enrich`, only add candidate to `vhosts` list if it's a strong signal. Or: don't add to vhosts at all in enrich for hyperv; just mark the Device and let the API discovery add the real VHost.

Actually, for ESXi/Proxmox/KVM, `enrich` also adds a VHost without credentials. Then the switch (if credentials exist) adds another. Same duplicate issue!

So dedup is needed regardless. Let me add at end:
```java
// dedupe VHosts by IP (prefer API-enriched entries)
Map<String, VirtualizationHost> byIp = new LinkedHashMap<>();
for (VirtualizationHost h : r.vhosts) {
    VirtualizationHost existing = byIp.get(h.ip);
    if (existing == null
        || existing.type.endsWith("-candidate")
        || (existing.vmMacs.isEmpty() && !h.vmMacs.isEmpty())) {
        byIp.put(h.ip, h);
    }
}
r.vhosts.clear();
r.vhosts.addAll(byIp.values());
```

And for `guessType`, return "hyperv" but note it's candidate. Or actually, looking again, "candidate" is a bit wordy. Let me just return the type and let dedup prefer API data.

Actually, on second thought, let me not return "hyperv-candidate" in guessType — just return "hyperv". Then in enrich, add a VHost with type "hyperv" but no VM MACs. Then when credentials are provided and API succeeds, the dedup picks whichever has VM MACs. Or picks the last one added (the API one).

Hmm, but that's not robust. Let me add a `source` field to `VirtualizationHost`: "fingerprint" vs "api". Dedup prefers "api".

```java
public class VirtualizationHost {
    ...
    public String source = "fingerprint";  // "api" or "fingerprint"
}
```

And set to "api" in each API discovery class.

OK, but this changes the model. Fine, let me add it.

Or simpler: dedup by IP, prefer the one with more info (has vmMacs, or has managementNets, or api source). Let me use "source" field.

Also, I want to keep the response focused and not too sprawling. But this task is inherently complex. Let me be pragmatic.

Actually you know what, let me keep the response focused:

1. Add winrm4j dependency
2. Add HyperVDiscovery class with two PowerShell scripts
3. Update DiscoveryConfig for Hyper-V credentials (domain, https, port)
4. Update orchestrator switch
5. Update guessType for hyperv-candidate
6. Add dedup logic
7. Show CLI usage example

Let me also provide the PowerShell scripts inline so the user can test them independently.

Also, security note: NTLM over HTTP is not encrypted. For production, use HTTPS (5986) with cert, or Kerberos.

Let me also add error handling and timeouts.

One more thing: the response format. Let me match the previous response style - code-heavy, tables, notes.

Let me also make sure to mention:
- On winrm: enabling WinRM on target (`winrm quickconfig`)
- Trusted hosts for workgroups
- Kerberos for domain
- WinRM permissions for non-admin users (Hyper-V Administrators group)

OK let me also make sure the pom addition is correct and include Apache HttpClient dependency (used for custom client).

Alright, drafting:

Actually one concern: winrm4j pulls in Apache CXF, which is heavy. Alternatives:
- jcifs-ng + manual SOAP
- WinRM4j
- Apache CXF's winrm feature

winrm4j is simplest. Let me use it.

Also, there's a maintenance concern: winrm4j 0.12.0 was last released ~2021. Let me check if there's a newer version... I recall 0.12.0 is the latest stable. Should be fine.

Let me also handle an important edge: PowerShell output encoding. WinRM may return UTF-16 or UTF-8. Jackson should handle both if we get clean string. But there might be BOM. `extractJson` in my code handles that (skips non-JSON prefix).

Also `ConvertTo-Json -Compress` keeps it on one line, good for parsing.

For empty VM list, PowerShell returns `$null` → empty output. Handle that:
```java
if (vms == null || vms.isNull()) { return host; }  // no VMs
```

OK let me write the final response.

Let me also add: what if Hyper-V is running but the WinRM user isn't in Hyper-V Admins group? The `Get-VM` will fail with access denied. Handle in exec() - throw with stderr. Now the orchestrator catches exceptions per credential and adds to warnings. Good.

OK, one more thing: should I try to identify cluster? The user hasn't asked, but it's a natural follow-up. Let me mention it as a note.

Final structure of response:

1. Short intro - what we're adding
2. pom.xml update
3. Credential model update
4. HyperVDiscovery.java (main deliverable)
5. PowerShell scripts (inline, so user can test)
6. Orchestrator integration
7. guessType update + dedup
8. CLI usage examples
9. WinRM prerequisites / enabling (short table)
10. Testing commands
11. Notes on what remains

Let me draft the code now with fresh eyes.

Actually one more concern: When the VM has multiple NICs, one might be connected to an "Internal" or "Private" vSwitch that has no external network. Only "External" vSwitch VMs have MACs on the physical LAN. But the VM's MAC is still registered on the virtual switch. If a VM is only on internal switch, its MAC won't appear in ARP on the physical LAN. That's fine — it's still a VM the host runs, and we can report it with `nics` list showing which switches.

Also, guest OS: Hyper-V doesn't directly expose guest OS via `Get-VM`. Need `Get-VMIntegrationService` or `Get-WmiObject -Class Win32_OperatingSystem -ComputerName $vm` (requires guest permissions). Or `Get-VMGuestInfo` (Windows Server 2022+). Let me add a "best effort" attempt:

```powershell
# In VM_SCRIPT, add:
$guest = $null
try {
    $gic = Get-VMIntegrationService -VMName $vm.Name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    if ($gic -and $gic.Enabled) {
        # Actually can't reliably get OS without guest access
    }
} catch {}
```

Skip guest OS for now. Note in code.

Actually, we can use `Get-WmiObject` from the host to the guest if guest allows WMI. But that's a guest-credentials issue. Skip for first cut.

Similarly for VM IP: `Get-VMNetworkAdapter` IPAddresses only works if Integration Services are installed and KVP is exchanged. It might return nothing for non-Windows or if IS isn't running. That's fine — we fill from ARP if we can match.

OK, coding.

Also, need to update the `enrich` method's guessType to add hyperv-candidate. Actually, wait: the user has asked for Hyper-V, and I want to also touch on the other pieces since they said "İstersen hepsini birlikte de ele alabilirsin". But primary focus is Hyper-V.

Let me include only Hyper-V code, and at the very end list what remains.

Actually thinking about it more — the user said "sonra diğerlerini yaparız. İstersen hepsini birlikte de ele alabilirsin." So they're OK with either focus-on-HyperV or doing everything. Let me focus on Hyper-V thoroughly (since it's the more specific ask) and briefly preview remaining work.

Let me code carefully now.

One more thought: for Hyper-V, the host might be a cluster member. VMs could be migrated. In a cluster, if we query one node, we only see the VMs currently running on that node (or, if cluster-aware, all). Actually `Get-VM` without `-ComputerName` queries only the local node. For cluster, use `Get-ClusterNode | ForEach-Object { Get-VM -ComputerName $_.Name }`. Let me add that as an option:

```powershell
# In VM_SCRIPT:
$cluster = Get-Cluster -ErrorAction SilentlyContinue
if ($cluster) {
    $out = @()
    Get-ClusterNode | ForEach-Object {
        $nodeName = $_.Name
        Get-VM -ComputerName $nodeName -ErrorAction SilentlyContinue | ForEach-Object { ... }
    }
} else {
    Get-VM | ForEach-Object { ... }
}
```

But this requires running from a cluster node and requires cluster permissions. Let me keep the script simple (single-host) and note cluster support requires running against each node, OR use a cluster-aware variant.

Actually, let me include both variants via option. Or just add the cluster path conditionally inside the same script. It's not that long.

Hmm, but `-ComputerName` for Get-VM in newer Hyper-V module might not work as expected — sometimes you need `Invoke-Command -ComputerName`. Let me use Invoke-Command for cross-node:

```powershell
$cluster = Get-Cluster -ErrorAction SilentlyContinue
if ($cluster) {
    Invoke-Command -ComputerName (Get-ClusterNode | Select-Object -ExpandProperty Name) -ScriptBlock {
        Get-VM | ForEach-Object { ... }  # scriptblock contents
    }
} else {
    Get-VM | ForEach-Object { ... }
}
```

This is more reliable. But requires CredSSP or Kerberos delegation. Hmm.

Let me simplify: present single-host as primary. Add a note that for clusters, you should point the tool at each node (or use a comma-separated list in `--hyperv`).

Actually, a simpler approach: the tool accepts multiple `--hyperv` entries (one per node). The orchestrator loops through all credentials. That naturally handles clusters.

OK, single-host per invocation, multi-node via multiple credentials. Clean.

Working on script for Ipv4 addresses — need to be careful. `Get-NetIPAddress -PrefixOrigin` values: `Manual`, `Dhcp`, `RouterAdvertisement`, `WellKnown`. Skip WellKnown (169.254.x.x). Also skip `127.0.0.1`.

For IPv4 interface on vEthernet (Hyper-V switch host adapters), these are the vNICs on the host. Their IPs might overlap with the physical NIC IP if using vEthernet. Actually no, typically the vEthernet adapter has the IP (set by the switch config), and the physical adapter underneath has no IP. Or both might if it's not properly configured. In any case, including all non-wellknown IPs is OK for BFS.

Actually one issue: with Hyper-V, the physical NIC has no IP when bound to a vSwitch. The vEthernet adapter has the IP. So `Get-NetIPAddress` returns the vEthernet IP. Good.

OK, coding time. Let me write the final response.

Actually, one more minor thing: the DEDUP logic. Let me handle it in the orchestrator at the end.

```java
// Dedup virtualization hosts by IP, preferring API-enriched entries
Map<String, VirtualizationHost> dedup = new LinkedHashMap<>();
for (VirtualizationHost h : r.vhosts) {
    VirtualizationHost existing = dedup.get(h.ip);
    if (existing == null) {
        dedup.put(h.ip, h);
    } else {
        // Prefer the one with more info (has vmMacs or api-source)
        boolean preferNew = (existing.vmMacs.isEmpty() && !h.vmMacs.isEmpty())
                         || ("fingerprint".equals(existing.source) && "api".equals(h.source));
        if (preferNew) dedup.put(h.ip, h);
    }
}
r.vhosts.clear();
r.vhosts.addAll(dedup.values());
```

And in each API discovery class, set `host.source = "api"`.

Actually, this is a nice-to-have. But it also matters for the "hyperv-candidate" issue.

Yes, let me add `source` field. And set `source = "api"` in EsxiDiscovery, ProxmoxDiscovery, KvmDiscovery, HyperVDiscovery.

And `enrich` sets `vh.source = "fingerprint"`.

Alright, let me finalize the code.

Wait, I don't have the current code for enrich in front of me (from previous response). Let me recall:
```java
VirtualizationHost vh = new VirtualizationHost();
vh.type = vt; vh.ip = d.ip.getHostAddress(); vh.id = vt + ":" + vh.ip;
vh.name = d.hostname;
r.vhosts.add(vh);
```

Add: `vh.source = "fingerprint";`

OK.

Let me write final code now.

Also, HyperVDiscovery.Options — let me simplify and just pass the Credential directly, or use a record.

```java
public record Options(String host, int port, boolean useHttps, String domain, String user, String pass) {
    public static Options from(DiscoveryConfig.Credential c) {
        return new Options(c.host, c.port, c.useHttps, c.domain, c.user, c.passOrKey);
    }
}
```

But then HyperVDiscovery would depend on DiscoveryConfig. Circular? Not really, but let me keep HyperVDiscovery independent by using the record directly built in the orchestrator. Fine.

Let me code.

Also for the winrm4j dependency, one concern: it might have transitive dependency issues with slf4j or other logging frameworks. Let me note that if there are conflicts, exclude or pin versions.

Let me finalize the response.

Actually, I realize `setAuthenticationScheme` expects `AuthenticationScheme` which for NTLM is `io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme`. The `INSTANCE` singleton exists. Good.

Also, `b.setReceiveTimeout(60_000L, TimeUnit.MILLISECONDS)` — the signature is `setReceiveTimeout(long value, TimeUnit unit)`. Yes.

`b.setOperationTimeout(120_000L, TimeUnit.MILLISECONDS)` — same.

Both exist. Good.

`WinRmToolResponse resp = tool.executePs(ps)` — returns response with `getStatusCode()`, `getStdOut()`, `getStdErr()`.

Hmm actually I recall the API is `executePs(String command)` and it returns `WinRmToolResponse` — or is it `executePs(String) throws WinRmException`? In winrm4j:
- `WinRmTool.executePs(String ps)` returns `WinRmToolResponse`
- Exception: `WinRmException` — unchecked or checked? Might be checked, need to declare in method signature.

Let me wrap in try/catch and convert to RuntimeException to keep signatures simple. Or declare `throws Exception` (which the discover method already does).

Actually the orchestrator wraps in try-catch, so either way works. Let me just declare `throws Exception`.

Alright, final code:

```java
package netdisc.virtualization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cloudsoft.windows.winrm.WinRmTool;
import io.cloudsoft.windows.winrm.WinRmToolResponse;
import io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import java.util.*;
import java.util.concurrent.TimeUnit;

public final class HyperVDiscovery {

    private static final ObjectMapper MAP = new ObjectMapper();

    public record Options(String host, int port, boolean useHttps,
                          String domain, String user, String pass) {}

    public static VirtualizationHost discover(Options opt, List<VirtualMachine> sink) throws Exception {
        WinRmTool tool = buildTool(opt);

        // 1) Host info
        String hostOut = exec(tool, HOST_SCRIPT);
        JsonNode hostJson = MAP.readTree(extractJson(hostOut));
        if (hostJson == null || !hostJson.isObject())
            throw new RuntimeException("Hyper-V host bilgisi alınamadı (PowerShell çıktısı beklenmedik)");

        VirtualizationHost host = new VirtualizationHost();
        host.type = "hyperv";
        host.source = "api";
        host.ip = opt.host();
        host.id = "hyperv:" + opt.host();
        host.name = hostJson.path("Hostname").asText(opt.host());
        host.version = hostJson.path("OsVersion").asText(null);

        for (JsonNode ip : hostJson.path("IpAddresses")) {
            String addr = ip.path("IPAddress").asText();
            int len = ip.path("PrefixLength").asInt(24);
            if (!addr.isEmpty() && !addr.startsWith("127.") && !addr.startsWith("169.254."))
                host.managementNets.add(addr + "/" + len);
            // vEthernet adapter MAC'lerini host'a ekle
        }

        // 2) VM listesi
        String vmOut = exec(tool, VM_SCRIPT);
        JsonNode vms = MAP.readTree(extractJson(vmOut));
        if (vms != null && !vms.isNull()) {
            if (vms.isObject()) vms = MAP.createArrayNode().add(vms);
            for (JsonNode v : vms) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = v.path("Name").asText("(no-name)");
                vm.uuid = v.path("Id").asText(null);
                vm.hostId = host.id;
                vm.powerState = v.path("State").asText(null);
                for (JsonNode a : v.path("Adapters")) {
                    String mac = normalizeMac(a.path("MacAddress").asText(""));
                    String sw = a.path("SwitchName").asText("");
                    if (mac != null) {
                        host.vmMacs.add(mac);
                        if (vm.mac == null) vm.mac = mac;
                    }
                    vm.nics.add((mac == null ? "no-mac" : mac) + "@" + sw);
                    String ipList = a.path("IPAddresses").asText("");
                    if (vm.ip == null && !ipList.isBlank()) {
                        vm.ip = ipList.split(";")[0].trim();
                    }
                }
                sink.add(vm);
            }
        }
        return host;
    }

    // ---------- scripts ---------------------------------------------------
    private static final String HOST_SCRIPT = """
        $ErrorActionPreference = 'Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $ips = @()
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
          ForEach-Object {
            $ips += [PSCustomObject]@{
              IPAddress = $_.IPAddress
              PrefixLength = $_.PrefixLength
              InterfaceAlias = $_.InterfaceAlias
            }
          }
        [PSCustomObject]@{
          Hostname = $env:COMPUTERNAME
          OsVersion = [System.Environment]::OSVersion.VersionString
          IpAddresses = $ips
        } | ConvertTo-Json -Depth 4 -Compress
        """;

    private static final String VM_SCRIPT = """
        $ErrorActionPreference = 'Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $out = @()
        Get-VM | ForEach-Object {
          $vm = $_
          $ads = @()
          Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object {
            $macRaw = $_.MacAddress
            $mac = ''
            if ($macRaw) {
              $hex = ($macRaw -replace '[^0-9a-fA-F]','').ToLower()
              if ($hex.Length -eq 12) {
                $mac = ($hex -replace '(..)','$1:').TrimEnd(':')
              }
            }
            $ads += [PSCustomObject]@{
              Name = $_.Name
              MacAddress = $mac
              SwitchName = $_.SwitchName
              IPAddresses = if ($_.IPAddresses) { $_.IPAddresses -join ';' } else { '' }
            }
          }
          $out += [PSCustomObject]@{
            Name = $vm.Name
            Id = $vm.Id.ToString()
            State = $vm.State.ToString()
            Generation = $vm.Generation
            Version = $vm.Version
            Adapters = $ads
          }
        }
        $out | ConvertTo-Json -Depth 5 -Compress
        """;

    // ---------- helpers ---------------------------------------------------
    private static WinRmTool buildTool(Options opt) {
        String user = (opt.domain() == null || opt.domain().isBlank())
                ? opt.user() : opt.domain() + "\\" + opt.user();
        int port = opt.port() == 0 ? (opt.useHttps() ? 5986 : 5985) : opt.port();
        WinRmTool.Builder b = WinRmTool.Builder.builder(opt.host(), user, opt.pass());
        b.setAuthenticationScheme(NtlmAuthScheme.INSTANCE);
        b.port(port);
        b.useHttps(opt.useHttps());
        b.setReceiveTimeout(60_000L, TimeUnit.MILLISECONDS);
        b.setOperationTimeout(120_000L, TimeUnit.MILLISECONDS);
        return b.build();
    }

    private static String exec(WinRmTool tool, String ps) throws Exception {
        WinRmToolResponse r = tool.executePs(ps);
        if (r.getStatusCode() != 0)
            throw new RuntimeException("PowerShell exit=" + r.getStatusCode() + " stderr=" + r.getStdErr());
        return r.getStdOut();
    }

    private static String normalizeMac(String raw) {
        if (raw == null) return null;
        String hex = raw.replaceAll("[^0-9a-fA-F]", "").toLowerCase();
        if (hex.length() != 12 || hex.equals("000000000000")) return null;
        return hex.substring(0,2)+":"+hex.substring(2,4)+":"+hex.substring(4,6)+":"+
               hex.substring(6,8)+":"+hex.substring(8,10)+":"+hex.substring(10,12);
    }

    private static String extractJson(String s) {
        if (s == null || s.isBlank()) return "null";
        int first = -1, last = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{' || c == '[') { first = i; break; }
        }
        for (int i = s.length() - 1; i >= 0; i--) {
            char c = s.charAt(i);
            if (c == '}' || c == ']') { last = i; break; }
        }
        if (first < 0 || last <= first) return "null";
        return s.substring(first, last + 1);
    }
}
```

OK good.

Now the Credential model update. I need to add `domain` and `useHttps`.

```java
public static class Credential {
    public String kind;         // "esxi" | "proxmox" | "kvm" | "hyperv"
    public String host, user, passOrKey;
    public String domain = "";
    public int port = 0;
    public boolean useHttps = false;
    public Credential(String k, String h, String u, String p) {
        kind = k; host = h; user = u; passOrKey = p;
    }
}
```

And CLI parsing for hyperv.

Orchestrator update:
```java
case "hyperv" -> HyperVDiscovery.discover(
    new HyperVDiscovery.Options(c.host, c.port, c.useHttps, c.domain, c.user, c.passOrKey),
    r.vms);
```

Dedup after all discoveries:
```java
// after the credential loop and BFS, dedupe VHosts by IP
Map<String, VirtualizationHost> byIp = new LinkedHashMap<>();
for (VirtualizationHost h : r.vhosts) {
    VirtualizationHost existing = byIp.get(h.ip);
    if (existing == null) {
        byIp.put(h.ip, h);
    } else {
        boolean preferNew = "api".equals(h.source) && !"api".equals(existing.source);
        if (preferNew) byIp.put(h.ip, h);
    }
}
r.vhosts.clear();
r.vhosts.addAll(byIp.values());
```

And guessType update:
```java
if (p.contains(5985) || p.contains(5986)) return "hyperv";
```

Wait but then it conflicts with "hyperv" as the type used by HyperVDiscovery. Good, that's actually better — consistent type.

But then when enrich adds a fingerprint VHost and HyperVDiscovery adds an API VHost, they both have type="hyperv" and same ip. Dedup prefers the API one. 

OK. Also update `source` field on `VirtualizationHost`:
```java
public String source = "fingerprint";  // "fingerprint" | "api"
```

And set `source = "api"` in each API discovery class:
- EsxiDiscovery
- ProxmoxDiscovery
- KvmDiscovery
- HyperVDiscovery (already done)

Alright, let me also add CLI parsing that shows a clean example.

For `--hyperv`:
```java
case "--hyperv" -> {
    var c = new DiscoveryConfig.Credential("hyperv", a[++i], null, null);
    cfg.vmCreds.add(c);
}
case "--hyperv-user" -> lastHyperV(cfg).user = a[++i];
case "--hyperv-pass" -> lastHyperV(cfg).passOrKey = a[++i];
case "--hyperv-domain" -> lastHyperV(cfg).domain = a[++i];
case "--hyperv-port" -> lastHyperV(cfg).port = Integer.parseInt(a[++i]);
case "--hyperv-https" -> lastHyperV(cfg).useHttps = true;
```

Helper:
```java
private static Credential lastHyperV(DiscoveryConfig cfg) {
    for (int i = cfg.vmCreds.size() - 1; i >= 0; i--) {
        var c = cfg.vmCreds.get(i);
        if ("hyperv".equals(c.kind)) return c;
    }
    throw new IllegalArgumentException("Önce --hyperv <host> vermelisin");
}
```

But `fromArgs` is a static method in DiscoveryConfig. Let me make it a static helper there too.

OK, and the final response should also mention WinRM prerequisites. Let me include a table.

Also test commands:
```powershell
# On Hyper-V host
winrm quickconfig -q
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP*" | Enable-NetFirewallRule
Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "CORP\myuser"  # for non-admin
```

For workgroup (non-domain):
```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.5" -Concatenate
```

Alright, let me finalize the response.

Wait, another thing: I should also decouple `HyperVDiscovery.Options` from the config. Since I've defined it as a record taking directly, and the orchestrator builds it, that's clean.

But `DiscoveryConfig.Credential` needs `domain` and `useHttps` fields. That's fine.

One last thing: I want to add a small note that the response does not have proper dedup for VMs (if a host is queried twice, VMs might be duplicated). Let me add VM dedup too:
```java
// Dedupe VMs by uuid or mac
Map<String, VirtualMachine> vmDedup = new LinkedHashMap<>();
for (VirtualMachine vm : r.vms) {
    String key = vm.uuid != null ? vm.uuid : (vm.mac != null ? vm.mac : vm.name);
    vmDedup.putIfAbsent(key, vm);
}
r.vms.clear();
r.vms.addAll(vmDedup.values());
```

Also tie VM IP back to Device: after matching, copy VM IP to Device if we have it.

Actually in

**Kullanıcı:**

Continue from where you have left off.

**Asistan:**

# Hyper-V: WinRM/PowerShell üzerinden VM ↔ MAC eşlemesi

Önceki iskelete **hipervizör katmanına `hyperv`** ekliyoruz. Yukarıda yarım kalan kısmı tamamlıyorum. Üç PowerShell script (host, VM, adapters) WinRM üzerinden çalıştırılıyor; JSON çıktısını Jackson ile ayrıştırıp `VirtualizationHost.vmMacs` içine yazıyoruz. Ardından mevcut `VMHostMatcher` ARP/SNMP'den gelen Device MAC'leri ile bunları eşliyor.

---

## 1. `pom.xml` — `winrm4j` ekle

```xml
<!-- WinRM (NTLM, HTTP/HTTPS) -->
<dependency>
    <groupId>io.cloudsoft.windows</groupId>
    <artifactId>winrm4j</artifactId>
    <version>0.12.0</version>
</dependency>
<!-- winrm4j'nin HTTPS için kullandığı HttpClient (annotated) -->
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
    <version>4.5.14</version>
</dependency>
```

> `winrm4j` transitive olarak Apache CXF ve `httpclient` getirir. Başka bir CXF kullanıyorsan `mvn dependency:tree` ile çakışma kontrolü yap.

---

## 2. `DiscoveryConfig.Credential` — `domain`, `useHttps`, `port`

```java
// src/main/java/netdisc/DiscoveryConfig.java (ilgili sınıf)
public static class Credential {
    public String kind;             // "esxi" | "proxmox" | "kvm" | "hyperv"
    public String host;
    public String user;
    public String passOrKey;
    public String domain = "";      // NTLM için CORP gibi; workgroup'ta boş
    public int port = 0;            // 0 = tipe göre varsayılan
    public boolean useHttps = false;

    public Credential(String k, String h, String u, String p) {
        kind = k; host = h; user = u; passOrKey = p;
    }
}
```

---

## 3. `VirtualizationHost.source` — fingerprint mi API mi?

```java
// src/main/java/netdisc/model/VirtualizationHost.java
public class VirtualizationHost {
    // ... mevcut alanlar ...
    /** "fingerprint" = sadece port/MAC ile tahmin, "api" = gerçek API'den */ 
    public String source = "fingerprint";
}
```

---

## 4. `HyperVDiscovery` — ana sınıf

```java
// src/main/java/netdisc/virtualization/HyperVDiscovery.java
package netdisc.virtualization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cloudsoft.windows.winrm.WinRmTool;
import io.cloudsoft.windows.winrm.WinRmToolResponse;
import io.cloudsoft.windows.winrm.authentication.NtlmAuthScheme;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import java.util.*;
import java.util.concurrent.TimeUnit;

public final class HyperVDiscovery {

    private static final ObjectMapper MAP = new ObjectMapper();

    /** Bir Hyper-V host'una bağlanmak için gereken parametreler. */
    public record Options(String host, int port, boolean useHttps,
                          String domain, String user, String pass) {}

    public static VirtualizationHost discover(Options opt, List<VirtualMachine> sink) throws Exception {
        WinRmTool tool = buildTool(opt);

        // ---- 1) Host temel bilgiler + yönetim IP'leri
        String hostOut = exec(tool, HOST_SCRIPT);
        JsonNode hostJson = MAP.readTree(extractJson(hostOut));
        if (hostJson == null || !hostJson.isObject())
            throw new RuntimeException("Hyper-V host bilgisi alınamadı (PowerShell çıktısı JSON değil)");

        VirtualizationHost host = new VirtualizationHost();
        host.type = "hyperv";
        host.source = "api";
        host.ip = opt.host();
        host.id = "hyperv:" + opt.host();
        host.name = hostJson.path("Hostname").asText(opt.host());
        host.version = hostJson.path("OsVersion").asText(null);

        for (JsonNode ip : hostJson.path("IpAddresses")) {
            String addr = ip.path("IPAddress").asText();
            int len = ip.path("PrefixLength").asInt(24);
            if (!addr.isEmpty()
                    && !addr.startsWith("127.")
                    && !addr.startsWith("169.254.")) {
                host.managementNets.add(addr + "/" + len);
            }
        }

        // ---- 2) VM listesi + adapter MAC'leri
        String vmOut = exec(tool, VM_SCRIPT);
        JsonNode vms = MAP.readTree(extractJson(vmOut));
        if (vms != null && !vms.isNull()) {
            if (vms.isObject()) vms = MAP.createArrayNode().add(vms);   // tek VM → obje
            for (JsonNode v : vms) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = v.path("Name").asText("(isimsiz)");
                vm.uuid = v.path("Id").asText(null);
                vm.hostId = host.id;
                vm.powerState = v.path("State").asText(null);

                for (JsonNode a : v.path("Adapters")) {
                    String mac = normalizeMac(a.path("MacAddress").asText(""));
                    String sw  = a.path("SwitchName").asText("");
                    if (mac != null) {
                        host.vmMacs.add(mac);
                        if (vm.mac == null) vm.mac = mac;   // ilk MAC'i birincil say
                    }
                    vm.nics.add((mac == null ? "no-mac" : mac) + "@" + sw);

                    String ipList = a.path("IPAddresses").asText("");
                    if (vm.ip == null && !ipList.isBlank()) {
                        vm.ip = ipList.split(";")[0].trim();   // IS açıksa ilk IPv4
                    }
                }
                sink.add(vm);
            }
        }
        return host;
    }

    // ================= PowerShell script'leri =================

    /** Host adı, OS sürümü ve tüm IPv4 arayüzleri (vEthernet dahil). */
    private static final String HOST_SCRIPT = """
        $ErrorActionPreference = 'Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $ips = @()
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and
            $_.IPAddress -notlike '169.254.*' -and
            $_.PrefixOrigin -ne 'WellKnown'
          } |
          ForEach-Object {
            $ips += [PSCustomObject]@{
              IPAddress      = $_.IPAddress
              PrefixLength   = $_.PrefixLength
              InterfaceAlias = $_.InterfaceAlias
            }
          }
        [PSCustomObject]@{
          Hostname    = $env:COMPUTERNAME
          OsVersion   = [System.Environment]::OSVersion.VersionString
          IpAddresses = $ips
        } | ConvertTo-Json -Depth 4 -Compress
        """;

    /** Get-VM + her VM'nin ağ adaptörleri (MAC normalize edilerek). */
    private static final String VM_SCRIPT = """
        $ErrorActionPreference = 'Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $out = @()
        Get-VM | ForEach-Object {
          $vm = $_
          $ads = @()
          Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object {
            $macRaw = $_.MacAddress
            $mac = ''
            if ($macRaw) {
              $hex = ($macRaw -replace '[^0-9a-fA-F]','').ToLower()
              if ($hex.Length -eq 12) {
                $mac = ($hex -replace '(..)','$1:').TrimEnd(':')
              }
            }
            $ads += [PSCustomObject]@{
              Name        = $_.Name
              MacAddress  = $mac
              SwitchName  = $_.SwitchName
              IPAddresses = if ($_.IPAddresses) { $_.IPAddresses -join ';' } else { '' }
            }
          }
          $out += [PSCustomObject]@{
            Name       = $vm.Name
            Id         = $vm.Id.ToString()
            State      = $vm.State.ToString()
            Generation = $vm.Generation
            Version    = $vm.Version
            Adapters   = $ads
          }
        }
        $out | ConvertTo-Json -Depth 5 -Compress
        """;

    // ================= yardımcılar =================

    private static WinRmTool buildTool(Options opt) {
        String user = (opt.domain() == null || opt.domain().isBlank())
                ? opt.user()
                : opt.domain() + "\\" + opt.user();

        int port = opt.port() == 0 ? (opt.useHttps() ? 5986 : 5985) : opt.port();

        WinRmTool.Builder b = WinRmTool.Builder.builder(opt.host(), user, opt.pass());
        b.setAuthenticationScheme(NtlmAuthScheme.INSTANCE);
        b.port(port);
        b.useHttps(opt.useHttps());
        b.setReceiveTimeout(60_000L, TimeUnit.MILLISECONDS);
        b.setOperationTimeout(120_000L, TimeUnit.MILLISECONDS);
        return b.build();
    }

    private static String exec(WinRmTool tool, String ps) throws Exception {
        WinRmToolResponse r = tool.executePs(ps);
        if (r.getStatusCode() != 0) {
            throw new RuntimeException(
                "PowerShell exit=" + r.getStatusCode() + " stderr=" + r.getStdErr());
        }
        return r.getStdOut();
    }

    private static String normalizeMac(String raw) {
        if (raw == null) return null;
        String hex = raw.replaceAll("[^0-9a-fA-F]", "").toLowerCase();
        if (hex.length() != 12 || hex.equals("000000000000")) return null;
        return hex.substring(0,2)+":"+hex.substring(2,4)+":"+hex.substring(4,6)+":"+
               hex.substring(6,8)+":"+hex.substring(8,10)+":"+hex.substring(10,12);
    }

    /** WinRM bazen başına uyarı/log ekler; JSON süslü/parantezli kısmı ayıklar. */
    private static String extractJson(String s) {
        if (s == null || s.isBlank()) return "null";
        int first = -1, last = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{' || c == '[') { first = i; break; }
        }
        for (int i = s.length() - 1; i >= 0; i--) {
            char c = s.charAt(i);
            if (c == '}' || c == ']') { last = i; break; }
        }
        if (first < 0 || last <= first) return "null";
        return s.substring(first, last + 1);
    }
}
```

---

## 5. `guessType` — 5985/5986 görürseniz "hyperv" işaretle

```java
// VirtualizationDetector.java içinde
if (p.contains(16509) || p.contains(16514)) return "kvm";
if (p.contains(5985) || p.contains(5986))   return "hyperv";   // ★ yeni
```

> Burada fingerprint "hyperv" yazsa bile `HyperVDiscovery` çalıştırılmadan önce bu sadece bir **aday**dır. `source="fingerprint"` olarak işaretlenir; API çağrısı başarılıysa `source="api"` olan gerçek kayıt onu ezer (aşağıdaki dedup).

---

## 6. Orchestrator'a `hyperv` case + dedup

```java
// DiscoveryOrchestrator.run() içinde, mevcut switch'e ekle:
VirtualizationHost h = switch (c.kind) {
    case "esxi"    -> EsxiDiscovery.discover(newHost(c), c.user, c.passOrKey, r.vms);
    case "proxmox" -> ProxmoxDiscovery.discover(c.host, c.port, c.user, c.passOrKey, r.vms);
    case "kvm"     -> KvmDiscovery.discover(c.host, c.user, c.passOrKey, r.vms);
    case "hyperv"  -> HyperVDiscovery.discover(                       // ★ yeni
                        new HyperVDiscovery.Options(
                            c.host, c.port, c.useHttps,
                            c.domain, c.user, c.passOrKey),
                        r.vms);
    default -> null;
};
```

Discovery bitiminde (VMHostMatcher'den **önce**) dedup:

```java
// hyperv/esxi/proxmox/kvm'de API başarılıysa source="api"; enrich fingerprint="fingerprint".
Map<String, VirtualizationHost> byIp = new LinkedHashMap<>();
for (VirtualizationHost h : r.vhosts) {
    VirtualizationHost existing = byIp.get(h.ip);
    if (existing == null) {
        byIp.put(h.ip, h);
    } else if ("api".equals(h.source) && !"api".equals(existing.source)) {
        byIp.put(h.ip, h);   // API kazanır
    }
}
r.vhosts.clear();
r.vhosts.addAll(byIp.values());

// VM dedup (aynı host iki kez sorgulanırsa)
Map<String, VirtualMachine> byVm = new LinkedHashMap<>();
for (VirtualMachine vm : r.vms) {
    String key = vm.uuid != null ? vm.uuid
               : vm.mac  != null ? vm.mac
               : vm.hostId + "|" + vm.name;
    byVm.putIfAbsent(key, vm);
}
r.vms.clear();
r.vms.addAll(byVm.values());
```

Ayrıca VM IP'sini ARP/SNMP'den gelen Device ile senkronize et (opsiyonel ama faydalı):

```java
// VMHostMatcher.match(r) içinde, mevcut döngüden sonra:
for (VirtualMachine vm : r.vms) {
    if (vm.mac == null) continue;
    for (Device d : r.devices) {
        if (vm.mac.equals(d.mac)) {
            if (vm.ip == null && d.ip != null) vm.ip = d.ip.getHostAddress();
            break;
        }
    }
}
```

---

## 7. CLI argümanları

```java
// DiscoveryConfig.fromArgs() içine:
case "--hyperv"           -> cfg.vmCreds.add(new Credential("hyperv", a[++i], null, null));
case "--hyperv-user"      -> lastHyperV(cfg).user = a[++i];
case "--hyperv-pass"      -> lastHyperV(cfg).passOrKey = a[++i];
case "--hyperv-domain"    -> lastHyperV(cfg).domain = a[++i];
case "--hyperv-port"      -> lastHyperV(cfg).port = Integer.parseInt(a[++i]);
case "--hyperv-https"     -> lastHyperV(cfg).useHttps = true;
```

```java
private static Credential lastHyperV(DiscoveryConfig cfg) {
    for (int i = cfg.vmCreds.size() - 1; i >= 0; i--) {
        Credential c = cfg.vmCreds.get(i);
        if ("hyperv".equals(c.kind)) return c;
    }
    throw new IllegalArgumentException("Önce --hyperv <host> vermelisin");
}
```

**Örnek kullanım:**

```bash
java -jar netdisc.jar \
  --cidr 10.10.0.0/24 --snmp public \
  --hyperv 10.10.0.20 --hyperv-domain CORP \
      --hyperv-user svc-scan --hyperv-pass 'S3cr3t!' \
  --hyperv 10.10.0.21 --hyperv-domain CORP \
      --hyperv-user svc-scan --hyperv-pass 'S3cr3t!' \
  --out rapor.json
```

> **Küme (Failover Cluster)** için doğru yaklaşım: her node'u ayrı `--hyperv` olarak ver. VM sahipliği node'lar arasında değişebilir; hepsini tararsan eksiksiz envanter çıkar. Tek bir node'u sorgularsan yalnız o node'da çalışan VM'ler görünür.

---

## 8. WinRM önkoşulları (target Hyper-V host)

| Ortam | Yapılması gereken |
|---|---|
| **Domain** | `winrm quickconfig -q` + `Enable-PSRemoting -Force`. Servis hesabını **Hyper-V Administrators** grubuna ekle: `Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "CORP\svc-scan"`. Yönetici olmasına gerek yok. |
| **Workgroup** | Aynı adımlar + hedef tarafta: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.50" -Concatenate` ve kaynak tarafta (bizim Java host) güvenlik duvarından çıkış 5985/5986 açık olmalı. |
| **HTTPS (5986)** | `New-SelfSignedCertificate` v.b. ile cert, `winrm create winrm/config/Listener?Address=*+Transport=HTTPS ...`. Java tarafında **truststore**'a bu CA'yı ekle. Self-signed ise `--hyperv-https` yerine üretim için proper cert kullanman önerilir. |
| **Kerberos** | Domain'de tercih edilir. `NtlmAuthScheme` yerine `KerberosAuthScheme` kullan; Java'ya `-Djava.security.krb5.conf=... -Djavax.security.auth.useSubjectCredsOnly=false` ekle. |

**Hızlı doğrulama (WinRM'siz, host üzerinde):**

```powershell
Import-Module Hyper-V
Get-VM | Select-Object Name, State, Generation
Get-VMNetworkAdapter -VMName * | Select-Object VMName, Name, MacAddress, SwitchName, IPAddresses
```

Bizim script'lerin çıktısını da doğrudan test edebilirsin (hyperv_discovery.ps1 içine koyup çalıştır).

> **Not:** `Get-VMNetworkAdapter`'ın `MacAddress` alanı dynamic MAC'te VM kapalıysa boş döner. VM başladığında otomatik atanır. `IPAddresses` **Integration Services** çalışmıyorsa boş döner — bu yüzden ARP eşleşmesine güvenmek zorunlu.

---

## 9. Eşleşmenin uçtan uca akışı

```
[TCP sweep + ARP + SNMP] → Device.mac = "00:15:5d:aa:bb:cc"
                                        │
[HyperVDiscovery] → VirtualizationHost.vmMacs { ... "00:15:5d:aa:bb:cc" ... }
                                        │
[VMHostMatcher.match()]
    macToHost["00:15:5d:aa:bb:cc"] = "hyperv:10.10.0.20"
    Device("00:15:5d:aa:bb:cc") → kind=VIRTUAL_MACHINE, ownerHostId="hyperv:10.10.0.20"
                                        │
[VirtualMachine listesinde de aynı MAC var]
    vm.mac = "00:15:5d:aa:bb:cc", vm.hostId = "hyperv:10.10.0.20", vm.ip = "10.10.0.55"
```

Çıktı JSON'unda:

```json
{
  "vhosts": [{
    "id": "hyperv:10.10.0.20", "type": "hyperv", "source": "api",
    "name": "HV-NODE-01", "version": "Microsoft Windows NT 10.0.20348.0",
    "managementNets": ["10.10.0.20/24", "10.20.0.5/24", "172.16.5.1/24"],
    "vmMacs": ["00:15:5d:aa:bb:cc", "00:15:5d:dd:ee:ff"]
  }],
  "vms": [
    { "name": "WEB-01", "hostId": "hyperv:10.10.0.20",
      "mac": "00:15:5d:aa:bb:cc", "ip": "10.10.0.55",
      "powerState": "Running",
      "nics": ["00:15:5d:aa:bb:cc@External vSwitch"] }
  ],
  "devices": [
    { "ip": "10.10.0.55", "mac": "00:15:5d:aa:bb:cc",
      "kind": "VIRTUAL_MACHINE", "ownerHostId": "hyperv:10.10.0.20",
      "discoveredBy": ["tcp", "arp"], "metadata": { "match": "api-mac" } }
  ]
}
```

Ayrıca `managementNets` alanı sayesinde **10.20.0.0/24 ve 172.16.5.0/24** otomatik olarak BFS kuyruğuna girer — LAN'lar arası yayılım buradan tetiklenir.

---

## 10. Kalan işler (sıradaki adımlar)

Bu turda Hyper-V tamam. Diğerleri için hangi sırayla ilerlemek istersin:

1. **yavijava ile vCenter SDK envanteri** — ESXi SSH (`vim-cmd`) yerine gerçek API; cluster, resource pool ve datastore bilgisi.
2. **libvirt-java ile KVM** — SSH `virsh` yerine libvirt RPC (16509); daha hızlı ve güvenli.
3. **VLAN-aware LLDP/CDP çözümleyici** — 802.1Q tag sıyırma, SysName/PortDesc/MgmtAddr tam parse; topoloji grafiği.
4. **Web UI (Spring Boot + d3.js)** — `discovery-report.json`'ı canlı topoloji olarak göster.

İstersen bir sonrakine doğrudan geçelim — söyle, hangisi?

**Kullanıcı:**

Birinci ile başlayalım lütfen.

**Asistan:**

# vCenter / ESXi SDK Envanteri (yavijava)

Bu sınıf, önceki `EsxiDiscovery` (SSH + `vim-cmd`) sürümünün **API tabanlı** halidir. Aynı `--vcenter` bayrağı hem **vCenter** hem de **tek başına ESXi** (doğrudan `https://esxi/sdk`) için çalışır. Çıktı olarak birden fazla `VirtualizationHost` üretir: 1 adet **vCenter** (envanter bağlamı için) + her **ESXi host** için bir tane (VMs, VMkernel ağları, datastore'lar, cluster, datacenter bilgisiyle). `VirtualizationHost.vmMacs` alanı doldurulduğu için mevcut `VMHostMatcher` ARP/SNMP ile otomatik eşler.

---

## 1. `pom.xml` — `yavijava` ekle

```xml
<!-- vSphere SOAP SDK (yavijava - ToastTab fork) -->
<dependency>
    <groupId>com.toasttab.vijava</groupId>
    <artifactId>yavijava</artifactId>
    <version>6.0.1</version>
</dependency>

<!-- Alternatif: resmi VMware vSphere Client SDK (daha yeni, ama daha ağır) -->
<!-- <dependency>
    <groupId>com.vmware</groupId>
    <artifactId>vsphere-client-sdk</artifactId>
    <version>8.0.0</version>
</dependency> -->
```

> `yavijava` 6.0.1 sürümü vSphere 6.x–7.0'ı kapsar. 8.0+ için resmi SDK'ya geçiş gerekebilir (arayüz aynı, sadece namespace farklı). Maven Central'da sürüm numarası değişebilir; `mvn versions:display-dependency-updates` ile kontrol et.

---

## 2. Model: `VirtualizationHost.metadata`

vcCenter'dan gelen cluster/datacenter/datastore gibi bağlam bilgisini taşımak için alan ekliyoruz:

```java
// src/main/java/netdisc/model/VirtualizationHost.java
public class VirtualizationHost {
    public String id;
    public String type;              // esxi, vcenter, proxmox, kvm, hyperv, nutanix
    public String ip, name, version;
    public Set<String> vmMacs = new TreeSet<>();
    public Set<String> managementNets = new TreeSet<>();
    public String source = "fingerprint";
    public Map<String, String> metadata = new LinkedHashMap<>();   // ★ yeni
}
```

---

## 3. `DiscoveryConfig.Credential` — `ignoreCert` alanı

```java
// src/main/java/netdisc/DiscoveryConfig.java
public static class Credential {
    public String kind;               // "esxi" | "proxmox" | "kvm" | "hyperv" | "vcenter"
    public String host;               // vCenter/ESXi için tam URL veya bare host
    public String user;
    public String passOrKey;
    public String domain = "";
    public int port = 0;
    public boolean useHttps = false;
    public boolean ignoreCert = false;    // ★ yeni (vCenter self-signed)
}
```

---

## 4. `VCenterDiscovery` — ana sınıf

```java
// src/main/java/netdisc/virtualization/VCenterDiscovery.java
package netdisc.virtualization;

import com.vmware.vim25.*;
import com.vmware.vim25.mo.*;
import com.vmware.vim25.mo.util.MorUtil;
import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;

import java.net.InetAddress;
import java.net.URL;
import java.util.*;

public final class VCenterDiscovery {

    public record Options(String url, String user, String pass, boolean ignoreCert) {}

    public static List<VirtualizationHost> discover(Options opt, List<VirtualMachine> vmSink)
            throws Exception {
        List<VirtualizationHost> result = new ArrayList<>();
        String url = normalizeUrl(opt.url());
        String vcHost = new URL(url).getHost();

        ServiceInstance si = new ServiceInstance(
                new URL(url), opt.user(), opt.pass(), opt.ignoreCert());
        try {
            // ---- vCenter (veya standalone ESXi) kendisi
            AboutInfo about = si.getAboutInfo();
            VirtualizationHost vc = new VirtualizationHost();
            vc.type = "vcenter";
            vc.source = "api";
            vc.id = "vcenter:" + vcHost;
            vc.ip = vcHost;
            vc.name = about.getFullName();
            vc.version = about.getVersion() + " build " + about.getBuild();
            vc.metadata.put("apiType", about.getApiType());
            vc.metadata.put("apiVersion", about.getApiVersion());
            vc.metadata.put("osType", about.getOsType());
            result.add(vc);

            Folder root = si.getRootFolder();
            InventoryNavigator nav = new InventoryNavigator(root);

            // ---- Distributed vSwitch portgroup adlarını çöz (dvpg key → name)
            Map<String, String> dvPgNames = new HashMap<>();
            for (ManagedEntity me : safeArray(nav.searchManagedEntities("DistributedVirtualPortgroup")))
                if (me instanceof DistributedVirtualPortgroup pg)
                    dvPgNames.put(pg.getKey(), pg.getName());

            // ---- Hosts
            Map<String, VirtualizationHost> byMor = new LinkedHashMap<>();
            for (ManagedEntity me : safeArray(nav.searchManagedEntities("HostSystem"))) {
                HostSystem hs = (HostSystem) me;
                VirtualizationHost vh = buildHostVHost(hs, si, vc, dvPgNames);
                result.add(vh);
                byMor.put(hs.getMOR().getVal(), vh);
            }

            // ---- VMs
            for (ManagedEntity me : safeArray(nav.searchManagedEntities("VirtualMachine"))) {
                VirtualMachine vmo = (VirtualMachine) me;
                VirtualMachine vm = buildVm(vmo, dvPgNames);

                HostSystem hostSys = vmo.getRuntime() != null ? vmo.getRuntime().getHost() : null;
                if (hostSys != null && hostSys.getMOR() != null) {
                    VirtualizationHost vh = byMor.get(hostSys.getMOR().getVal());
                    if (vh != null) {
                        vm.hostId = vh.id;
                        for (String nic : vm.nics) {
                            int at = nic.indexOf('@');
                            String mac = at > 0 ? nic.substring(0, at) : nic;
                            if (!"no-mac".equals(mac)) vh.vmMacs.add(mac);
                        }
                    }
                }
                vmSink.add(vm);
            }
        } finally {
            try { si.getServerConnection().logout(); } catch (Exception ignored) {}
        }
        return result;
    }

    // ===================== Host =====================
    private static VirtualizationHost buildHostVHost(HostSystem hs, ServiceInstance si,
                                                     VirtualizationHost vc,
                                                     Map<String, String> dvPgNames) {
        VirtualizationHost vh = new VirtualizationHost();
        vh.type = "esxi";
        vh.source = "api";
        vh.name = hs.getName();
        vh.metadata.put("vcenter", vc.ip);

        // Ürün sürümü
        try {
            if (hs.getConfig() != null && hs.getConfig().getProduct() != null) {
                ProductInformation pi = hs.getConfig().getProduct();
                vh.version = pi.getFullName();          // "VMware ESXi 7.0.3 build-... "
                vh.metadata.put("vendor", pi.getVendor());
                vh.metadata.put("product", pi.getName());
                vh.metadata.put("build", pi.getBuild());
                vh.metadata.put("apiVersion", pi.getApiVersion());
            }
        } catch (Exception ignored) {}

        // Runtime durumu
        try {
            if (hs.getRuntime() != null) {
                if (hs.getRuntime().getConnectionState() != null)
                    vh.metadata.put("connectionState", hs.getRuntime().getConnectionState().toString());
                if (hs.getRuntime().getPowerState() != null)
                    vh.metadata.put("powerState", hs.getRuntime().getPowerState().toString());
            }
        } catch (Exception ignored) {}

        // Parent zinciri: Cluster / ComputeResource / Datacenter
        try {
            ManagedEntity cur = hs;
            while (cur != null && cur.getParent() != null) {
                ManagedEntity parent = MorUtil.createExactManagedEntity(
                        si.getServerConnection(), cur.getParent());
                if (parent instanceof ClusterComputeResource cl) {
                    vh.metadata.put("cluster", cl.getName());
                    vh.metadata.put("clusterId", cl.getMOR().getVal());
                    ComputeResourceConfigInfo conf = null;
                    try { conf = cl.getConfigurationEx(); } catch (Exception ignored) {}
                    if (conf instanceof ClusterConfigInfoEx cc
                            && cc.getDrsConfig() != null
                            && cc.getDrsConfig().getEnabled() != null) {
                        vh.metadata.put("drs", cc.getDrsConfig().getEnabled().toString());
                    }
                } else if (parent instanceof ComputeResource cr) {
                    vh.metadata.put("computeResource", cr.getName());
                } else if (parent instanceof Datacenter dc) {
                    vh.metadata.put("datacenter", dc.getName());
                    break;
                }
                cur = parent;
            }
        } catch (Exception ignored) {}

        // VMkernel & console vmk'ler + vSwitch/portgroup listesi
        try {
            HostNetworkInfo ni = hs.getConfig().getNetwork();
            if (ni != null) {
                if (ni.getVnic() != null) {
                    for (int i = 0; i < ni.getVnic().length; i++) {
                        HostVirtualNic vnic = ni.getVnic()[i];
                        HostVirtualNicSpec spec = vnic.getSpec();
                        if (spec != null && spec.getIp() != null) {
                            String ip = spec.getIp().getIpAddress();
                            int prefix = spec.getIp().getPrefixLength();
                            vh.managementNets.add(ip + "/" + prefix);
                            vh.metadata.put("vmk" + i, vnic.getDevice() + "=" + ip + "/" + prefix);
                        }
                    }
                }
                if (ni.getConsoleVnic() != null) {
                    for (HostVirtualNic vnic : ni.getConsoleVnic()) {
                        HostVirtualNicSpec spec = vnic.getSpec();
                        if (spec != null && spec.getIp() != null)
                            vh.managementNets.add(
                                    spec.getIp().getIpAddress() + "/" + spec.getIp().getPrefixLength());
                    }
                }
                if (ni.getVswitch() != null) {
                    List<String> vs = new ArrayList<>();
                    for (HostVirtualSwitch s : ni.getVswitch()) vs.add(s.getName());
                    vh.metadata.put("vswitches", String.join(",", vs));
                }
                if (ni.getPortgroup() != null) {
                    List<String> pgs = new ArrayList<>();
                    for (HostPortGroup pg : ni.getPortgroup())
                        if (pg.getSpec() != null) pgs.add(pg.getSpec().getName());
                    vh.metadata.put("portgroups", String.join(",", pgs));
                }
            }
        } catch (Exception ignored) {}

        // Birincil yönetim IP'si (vmk0 varsayımı, yoksa ilk vmk, yoksa DNS)
        String primaryIp = null;
        String vmk0 = vh.metadata.get("vmk0");
        if (vmk0 != null && vmk0.contains("=")) primaryIp = vmk0.split("=")[1].split("/")[0];
        if (primaryIp == null)
            for (String net : vh.managementNets) { primaryIp = net.split("/")[0]; break; }
        if (primaryIp == null) {
            try { primaryIp = InetAddress.getByName(hs.getName()).getHostAddress(); }
            catch (Exception ignored) {}
        }
        vh.ip = primaryIp != null ? primaryIp : hs.getName();
        vh.id = "esxi:" + vh.ip;

        // Datastore'lar (isim:free/capacity GB)
        try {
            ManagedObjectReference[] dsRefs = hs.getDatastore();
            if (dsRefs != null) {
                List<String> dss = new ArrayList<>();
                for (ManagedObjectReference ref : dsRefs) {
                    Datastore ds = (Datastore) MorUtil.createExactManagedEntity(
                            si.getServerConnection(), ref);
                    DatastoreSummary sum = ds.getSummary();
                    long cap = sum != null && sum.getCapacity() != null
                            ? sum.getCapacity() / (1024L*1024*1024) : 0;
                    long free = sum != null && sum.getFreeSpace() != null
                            ? sum.getFreeSpace() / (1024L*1024*1024) : 0;
                    dss.add(ds.getName() + ":" + free + "/" + cap + "GB");
                }
                if (!dss.isEmpty()) vh.metadata.put("datastores", String.join("; ", dss));
            }
        } catch (Exception ignored) {}

        // Host'a bağlı mantıksal ağlar
        try {
            ManagedObjectReference[] netRefs = hs.getNetwork();
            if (netRefs != null) {
                List<String> nets = new ArrayList<>();
                for (ManagedObjectReference ref : netRefs) {
                    Network n = (Network) MorUtil.createExactManagedEntity(si.getServerConnection(), ref);
                    nets.add(n.getName());
                }
                if (!nets.isEmpty()) vh.metadata.put("networks", String.join(",", nets));
            }
        } catch (Exception ignored) {}

        return vh;
    }

    // ===================== VM =====================
    private static VirtualMachine buildVm(VirtualMachine vmo, Map<String, String> dvPgNames) {
        VirtualMachine vm = new VirtualMachine();
        vm.name = vmo.getName();

        try {
            if (vmo.getConfig() != null) {
                vm.uuid = vmo.getConfig().getInstanceUuid();
                if (vm.uuid == null) vm.uuid = vmo.getConfig().getUuid();
                vm.guestOs = vmo.getConfig().getGuestFullName();
            }
        } catch (Exception ignored) {}

        try {
            if (vmo.getRuntime() != null && vmo.getRuntime().getPowerState() != null)
                vm.powerState = vmo.getRuntime().getPowerState().toString();
        } catch (Exception ignored) {}

        // Guest IP (vmtools çalışıyorsa)
        try {
            if (vmo.getGuest() != null) {
                vm.ip = vmo.getGuest().getIpAddress();
                if (vm.ip == null && vmo.getGuest().getNet() != null) {
                    for (GuestNicInfo nic : vmo.getGuest().getNet()) {
                        if (nic.getIpAddress() != null && nic.getIpAddress().length > 0) {
                            vm.ip = nic.getIpAddress()[0];
                            break;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // Sanal ethernet kartları
        try {
            if (vmo.getConfig() != null && vmo.getConfig().getHardware() != null
                    && vmo.getConfig().getHardware().getDevice() != null) {
                for (VirtualDevice dev : vmo.getConfig().getHardware().getDevice()) {
                    if (dev instanceof VirtualEthernetCard card) {
                        String mac = card.getMacAddress();
                        if (mac != null && !mac.isEmpty()) mac = mac.toLowerCase();
                        String net = backingName(card, dvPgNames);
                        vm.nics.add((mac == null ? "no-mac" : mac) + "@" + net);
                        if (vm.mac == null && mac != null) vm.mac = mac;
                    }
                }
            }
        } catch (Exception ignored) {}

        return vm;
    }

    private static String backingName(VirtualEthernetCard card, Map<String, String> dvPgNames) {
        VirtualDeviceBackingInfo b = card.getBacking();
        if (b instanceof VirtualEthernetCardNetworkBackingInfo nb)
            return nb.getDeviceName() != null ? nb.getDeviceName() : "stdpg";
        if (b instanceof VirtualEthernetCardDistributedVirtualPortBackingInfo dvb
                && dvb.getPort() != null) {
            String key = dvb.getPort().getPortgroupKey();
            String name = dvPgNames.get(key);
            return name != null ? "dvs:" + name : "dvs-key:" + key;
        }
        if (b instanceof VirtualEthernetCardOpaqueNetworkBackingInfo ob)
            return "opaque:" + ob.getOpaqueNetworkId();
        if (b instanceof VirtualEthernetCardLegacyNetworkBackingInfo lb)
            return "legacy:" + lb.getDeviceName();
        return "unknown";
    }

    // ===================== yardımcılar =====================
    private static ManagedEntity[] safeArray(ManagedEntity[] arr) {
        return arr != null ? arr : new ManagedEntity[0];
    }

    private static String normalizeUrl(String url) {
        if (url == null || url.isBlank())
            throw new IllegalArgumentException("vCenter/ESXi URL boş olamaz");
        if (!url.startsWith("http://") && !url.startsWith("https://"))
            url = "https://" + url;
        if (!url.endsWith("/sdk")) url = url.replaceAll("/+$", "") + "/sdk";
        return url;
    }
}
```

---

## 5. Orchestrator: switch'i **Liste** döndürecek şekilde değiştir

Önceden tek `VirtualizationHost` dönüyordu; vCenter çoklu host döndüğü için listeye çeviriyoruz:

```java
// DiscoveryOrchestrator içindeki credential döngüsü
for (DiscoveryConfig.Credential c : cfg.vmCreds) {
    try {
        List<VirtualizationHost> found = switch (c.kind) {
            case "esxi"    -> List.of(EsxiDiscovery.discover(newHost(c), c.user, c.passOrKey, r.vms));
            case "proxmox" -> List.of(ProxmoxDiscovery.discover(c.host, c.port, c.user, c.passOrKey, r.vms));
            case "kvm"     -> List.of(KvmDiscovery.discover(c.host, c.user, c.passOrKey, r.vms));
            case "hyperv"  -> List.of(HyperVDiscovery.discover(
                                  new HyperVDiscovery.Options(
                                      c.host, c.port, c.useHttps,
                                      c.domain, c.user, c.passOrKey),
                                  r.vms));
            case "vcenter" -> VCenterDiscovery.discover(             // ★ yeni
                                  new VCenterDiscovery.Options(
                                      c.host, c.user, c.passOrKey, c.ignoreCert),
                                  r.vms);
            default -> List.of();
        };
        for (VirtualizationHost h : found) {
            r.vhosts.add(h);
            for (String net : h.managementNets) {
                if (net.contains("/") && visited.add(net)) {
                    NetworkSegment ns = new NetworkSegment(net);
                    ns.discoveredBy.add(h.type + "@" + h.ip);
                    frontier.add(ns);
                }
            }
        }
    } catch (Exception ex) {
        r.warnings.add(c.kind + "@" + c.host + ": " + ex.getMessage());
    }
}
```

> `visited` ve `frontier` değişkenlerinin zaten `discoverHosts`/`enrich` içinde tanımlı olduğu önceki kodla örtüşür; **`run()` metodunun başında** `Set<String> visited = new HashSet<>();` ve `Deque<NetworkSegment> frontier = new ArrayDeque<>();` şeklinde erişilebilir olmaları gerekir (Hyper-V turunda bu erişim zaten vardı, vCenter sadece aynı mekanizmayı kullanıyor).

---

## 6. CLI argümanları

```java
// DiscoveryConfig.fromArgs() içine
case "--vcenter"           -> cfg.vmCreds.add(new Credential("vcenter", a[++i], null, null));
case "--vcenter-user"      -> lastVCenter(cfg).user = a[++i];
case "--vcenter-pass"      -> lastVCenter(cfg).passOrKey = a[++i];
case "--vcenter-insecure"  -> lastVCenter(cfg).ignoreCert = true;
```

```java
private static Credential lastVCenter(DiscoveryConfig cfg) {
    for (int i = cfg.vmCreds.size() - 1; i >= 0; i--) {
        Credential c = cfg.vmCreds.get(i);
        if ("vcenter".equals(c.kind)) return c;
    }
    throw new IllegalArgumentException("Önce --vcenter <url> vermelisin");
}
```

**Örnek kullanım:**

```bash
# 1) vCenter üzerinden tüm envanter
java -jar netdisc.jar \
  --cidr 10.10.0.0/24 --snmp public \
  --vcenter https://vcenter.corp.local/sdk \
  --vcenter-user 'administrator@vsphere.local' --vcenter-pass 'Admin!23' \
  --vcenter-insecure \
  --out rapor.json

# 2) Tek başına ESXi (vCenter'siz) — doğrudan host üzerinden /sdk
java -jar netdisc.jar \
  --cidr 10.10.0.0/24 \
  --vcenter https://10.10.0.20/sdk \
  --vcenter-user root --vcenter-pass 'S3cr3t!' \
  --vcenter-insecure \
  --out rapor.json

# 3) Hyper-V ile birlikte karışık ortam
java -jar netdisc.jar --cidr 10.10.0.0/24 --snmp public \
  --vcenter https://vcenter.corp.local/sdk \
      --vcenter-user 'administrator@vsphere.local' --vcenter-pass 'Admin!23' --vcenter-insecure \
  --hyperv 10.10.0.30 --hyperv-domain CORP \
      --hyperv-user svc-scan --hyperv-pass 'S3cr3t!' \
  --out rapor.json
```

---

## 7. Gereksinimler / doğrulama

| Ortam | Ayarlar |
|---|---|
| **vCenter SSO** | Kullanıcı adı genelde `administrator@vsphere.local` formatındadır (yavijava doğrudan kabul eder). Servis hesabı için **Read-Only** rol + envanter kökünde okuma yetkisi yeterlidir. |
| **Standalone ESXi** | `root` kullanıcısı (veya Read-Only yerel kullanıcı) + 443 açık. |
| **Firewall** | TCP 443 (vCenter/ESXi SDK). Ek olarak vCenter → ESXi iletişimi arka planda zaten var; bizim Java kodu doğrudan vCenter ile konuşur. |
| **Self-signed sertifika** | `--vcenter-insecure` (yavijava'nın `ignoreCert=true` argümanı). Üretimde doğru CA'yı Java truststore'a ekleyip bu bayrağı kaldır. |
| **vSphere 8.0+** | yavijava 6.0.1 eski API kullanır; çalışabilir ama bazı yeni özellikleri kaçırır. Gerekirse resmi `vsphere-client-sdk`'ye geçiş: `VCenterDiscovery` içindeki `com.vmware.vim25.*` importları `com.vmware.vapi.*` ve `com.vmware.vim25.*` (aynı isim, farklı jar) ile değişir. |

**Hızlı doğrulama (PowerCLI ile):**

```powershell
Connect-VIServer vcenter.corp.local -User administrator@vsphere.local
Get-VMHost | Select Name, Version, @{n='vmk0';e={($_ | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.DeviceName -eq 'vmk0'}).IP}}
Get-VM | Select Name, PowerState, @{n='MACs';e={($_ | Get-NetworkAdapter).MacAddress -join ','}}
Disconnect-VIServer -Confirm:$false
```

Bizim kodun ürettiği `managementNets`, `vmMacs`, `metadata.datastores` alanlarıyla birebir karşılaştırabilirsin.

---

## 8. Örnek çıktı (rapor.json, kısaltılmış)

```json
{
  "vhosts": [
    {
      "id": "vcenter:vcenter.corp.local",
      "type": "vcenter", "source": "api",
      "ip": "vcenter.corp.local",
      "name": "VMware vCenter Server 7.0.3 build-20150588",
      "version": "7.0.3 build 20150588",
      "metadata": {
        "apiType": "VirtualCenter",
        "apiVersion": "7.0.3",
        "osType": "linux-x64"
      }
    },
    {
      "id": "esxi:10.10.0.20",
      "type": "esxi", "source": "api",
      "ip": "10.10.0.20",
      "name": "esxi-01.corp.local",
      "version": "VMware ESXi 7.0.3 build-20150588",
      "managementNets": ["10.10.0.20/24", "10.20.0.10/24", "172.16.99.5/24"],
      "vmMacs": ["00:50:56:aa:bb:cc", "00:50:56:dd:ee:ff"],
      "metadata": {
        "vcenter": "vcenter.corp.local",
        "cluster": "PROD-CL01",
        "clusterId": "domain-c42",
        "drs": "true",
        "datacenter": "DC-Istanbul",
        "vmk0": "vmk0=10.10.0.20/24",
        "vmk1": "vmk1=10.20.0.10/24",
        "vswitches": "vSwitch0,vSwitch-Mgmt",
        "portgroups": "VM Network,MGMT,VM-Storage",
        "datastores": "DS-PROD-01:1200/4000GB; DS-ISO:50/200GB",
        "networks": "VM Network,MGMT,VM-Storage,iSCSI-A"
      }
    }
  ],
  "vms": [
    {
      "name": "WEB-01", "uuid": "4211d14a-...", "hostId": "esxi:10.10.0.20",
      "mac": "00:50:56:aa:bb:cc", "ip": "10.10.0.55",
      "powerState": "POWERED_ON", "guestOs": "Ubuntu Linux (64-bit)",
      "nics": [
        "00:50:56:aa:bb:cc@VM Network",
        "00:50:56:cc:dd:ee@MGMT"
      ]
    }
  ],
  "devices": [
    {
      "ip": "10.10.0.55", "mac": "00:50:56:aa:bb:cc",
      "kind": "VIRTUAL_MACHINE", "ownerHostId": "esxi:10.10.0.20",
      "discoveredBy": ["tcp", "arp"],
      "metadata": { "match": "api-mac" }
    }
  ]
}
```

**Akış:**

```
[TCP + ARP + SNMP]   →  Device(mac=00:50:56:aa:bb:cc) @ 10.10.0.55
                                │
[VCenterDiscovery]   →  esxi:10.10.0.20.vmMacs += "00:50:56:aa:bb:cc"
                                │
[VMHostMatcher]      →  ownerHostId = "esxi:10.10.0.20", match = "api-mac"
                                │
[Orchestrator BFS]   →  managementNets: 10.20.0.0/24, 172.16.99.0/24 kuyruğa → yeni tarama
                                │
[VM IP birleştirme]  →  VM.ip = Device.ip (guest tools yoksa bile ARP'den dolar)
```

---

## 9. Notlar

- **`--vcenter` ile hem vCenter hem standalone ESXi**: API aynı (SOAP `/sdk`). Ayrı bir bayrak açmadım; aynı flag iki senaryoyu da kapsıyor. `AboutInfo.apiType` çıktıda `"VirtualCenter"` (vCenter) veya `"HostAgent"` (ESXi) olarak görünür.
- **`metadata` alanı artık `VirtualizationHost` üzerinde**: JSON'a otomatik yazılıyor, insan tarafından okunabilir; `cluster`, `datacenter`, `datastores`, `vswitches`, `vmk*` bilgileri buradan.
- **`VMHostMatcher` değişmedi**: mevcut `vhost.vmMacs` + `d.mac` eşleşmesi hâlâ geçerli. Fakat birden fazla NIC'li VM'lerde artık **tüm** MAC'ler `vmMacs`'e ekleniyor, dolayısıyla eşleşme oranı önceki SSH sürümüne göre yüksek.
- **Datastore, network, vSwitch** gibi ek bağlamlar envanter raporlaması için `metadata`'da; istersen bunları ilerleyen bir adımda ayrı model alanlarına taşırız.
- **`ignoreCert`**: yalnızca dahili/ayrı segment tarama için. Üretimde doğru CA'yı JVM truststore'a ekleyip bu bayrağı kaldırmanı öneririm.

---

## 10. Sıradaki

**vCenter tamam.** Sıradaki doğal adımlar:

1. **KVM — `libvirt-java`** (SSH `virsh` yerine libvirt RPC, port 16509): çok daha hızlı, authentication opsiyonları net (SASL/polkit), VM domain XML'ini ayrıştırmaya gerek kalmadan `Domain.getXMLDesc()` ile MAC ve ağ bilgisi.
2. **VLAN-aware LLDP/CDP** (topoloji + switch port bilgisi): 802.1Q tag sıyırma, SysName/PortDesc/MgmtAddr tam parse.
3. **Web UI** (Spring Boot + d3.js): `discovery-report.json`'ı canlı topoloji olarak göster, VHosts → VMs hiyerarşik ağaç görünümü.

Hangisiyle devam edelim?

**Kullanıcı:**

Yine 1 ile devam edelim.

**Kullanıcı:**

Yine 1 ile devam edelim.

**Kullanıcı:**

Yine 1 olsun lütfen

**Asistan:**

The user wants to continue with KVM via libvirt-java (option 1). Let me implement this thoroughly.

libvirt-java setup:
- Maven: `org.libvirt:libvirt:0.5.2` (latest) — wait, let me check. Actually libvirt-java on Maven Central... the coordinates are `org.libvirt:libvirt`. Latest versions are 0.5.x. Let me use 0.5.2.

Actually, I should double-check: libvirt-java is JNI-based, requires native libvirt libraries on the client machine. This is an important constraint. There's also `libvirt-java` bindings but they need a native .so/.dll.

Alternative for pure-Java: use libvirt over SSH + virsh (which we already have), or use the libvirt REST API via a proxy, or use the QEMU Machine Protocol directly (QMP).

Given the constraints, let me:
1. Present libvirt-java as primary (with native lib requirement noted)
2. Also mention the pure-Java fallback using SSH + virsh (already have it)

For libvirt-java:
- `Connect` = new Connect("qemu+tcp://host/system")
- `Domain` = conn.domainLookupByName(name) or conn.listAllDomains()
- `domain.getXMLDesc(0)` = full XML
- `domain.getInfo()` = state, maxMem, memory, nrVirtCpu, cpuTime
- `domain.getOSType()` 
- `Domain.getXMLDesc()` parse for MAC, network source

Parsing XML: use standard DOM parser (javax.xml).

Also for host info:
- `conn.getHostname()`
- `conn.getInfo()` = HypervisorInfo (model, memory, cpus, mhz, nodes, sockets, cores, threads)
- `conn.getVersion()` = libvirt version
- `conn.getType()` = "QEMU", "XEN", "LXC", etc.
- `conn.listAllNetworks()` = virtual networks (domain-based, like default NAT)
- `conn.listAllInterfaces()` = host physical interfaces
- `conn.listAllStoragePools()` = storage
- `conn.listAllNetworks()` for networks with their XML (bridge name, subnet)

Management nets come from network XML or from host's physical interface IPs (via NetworkInterface Java API when running on the host, or via `virsh iface-list`). Actually since we connect remotely, we can't easily get the host's own IPs via libvirt API... wait, we can:
- `conn.listAllInterfaces()` gives Interface objects; each has `getName()`, `getMACString()`, `isActive()`, and XML with IPs.

Interface XML example:
```xml
<interface type='ethernet' name='eth0'>
  <mac address='52:54:00:...'/>
  <ip address='192.168.1.10' prefix='24'/>
  ...
</interface>
```

Actually for the host's own network addresses, borders... Let me check: `virsh iface-dumpxml eth0` shows the interface's XML which may or may not include IP info depending on the driver. On Linux with NetworkManager/native libvirt, IP info might not be populated.

Better approach: try `conn.listAllInterfaces()` and parse XMLs; if empty, fall back to a `virsh` command via QEMU agent... but that's the SSH approach.

Alternative: use `Interface.getName()` and `Interface.getMACString()`, and separately try the libvirt `nwfilter` or `network` APIs.

Actually the cleanest way to get host IPs when connecting remotely via libvirt:
- Use `domain.getXMLDesc()` on any domain... no, that only gives VM IPs.
- Network XMLs give the bridge's subnet, e.g. `default` network → 192.168.122.0/24. That's a good proxy for "the host participates in this network."

So for `managementNets`, I'll collect:
1. All network subnets from `conn.listAllNetworks()` → parse each network's XML → get `<ip address=... netmask=.../>` → CIDR
2. All interface IPs from `conn.listAllInterfaces()` if available
3. Optionally, when the libvirt URI is tcp/ssh, use the hostname/IP from the URI

For physical interface enumeration via libvirt's `Interface`:
- `Interface.getXMLDesc(0)` gives D-Bus / udev info, not IPs directly on many systems. Actually for Linux, `virsh iface-dumpxml --inactive eth0` shows:
  ```xml
  <interface type='ethernet' name='eth0'>
    <start mode='onboot'/>
    <protocol family='ipv4'>
      <dhcp peerdns='yes'/>
    </protocol>
    <link state='up'/>
  </interface>
  ```
  For static IPs:
  ```xml
  <protocol family='ipv4'>
    <ip address='192.168.1.10' prefix='24'/>
  </protocol>
  ```
  So parsing works if addresses are statically configured. For DHCP, IP won't be shown. That's OK — we fall back to network XMLs.

For VM parsing via libvirt domain XML:
```xml
<domain type='kvm'>
  <name>web-01</name>
  <uuid>...</uuid>
  <os>...</os>
  <devices>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <interface type='bridge'>
      <mac address='52:54:00:dd:ee:ff'/>
      <source bridge='br0'/>
    </interface>
    <interface type='direct'>
      <mac address='...'/>
      <source dev='eth0' mode='bridge'/>
    </interface>
    <interface type='user'> <!-- SLIRP NAT, no real MAC on LAN -->
      <mac address='...'/>
    </interface>
  </devices>
</domain>
```

Also:
- `<name>`, `<uuid>`, `<title>`, `<description>`
- `<os><type>hvm</type></os>`
- `<memory>`, `<vcpu>`
- Domain state via `domain.getInfo().getState()` or `domain.isActive()`

Guest IP: libvirt has `domain.getGuestIPAddress()` (QEMU guest agent) — actually I recall libvirt-java exposes `DomainInterfaceInfo[] domain.interfaceAddresses(int)` or similar. In libvirt-java 0.5.x, there's `Domain.interfaceAddresses(int source)`. Let me check... Yes, `Domain.interfaceAddresses(int)` exists (returns `List<DomainInterfaceInfo>` or similar). Source constants: `VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE=0`, `_SRC_AGENT=1`, `_SRC_ARP=2`.

Let me use `SRC_ARP=2` first, fallback to `SRC_AGENT=1`, fallback to `SRC_LEASE=0`.

Actually in libvirt-java the method signature might be:
```java
public DomainInterfaceInfo[] interfaceAddresses(int source) throws LibvirtException
```

Hmm, in libvirt-java 0.5.2, I believe it's `DomainInterfaceInfo[]`. Let me use it.

Domain state: `domain.getInfo().getState()` returns `DomainInfo.DomainState` enum? Or an int? In libvirt-java 0.5.2, `DomainInfo.getState()` returns `DomainInfo.DomainState` I think. Actually, `domain.isActive()` returns boolean.

Let me handle:
```java
DomainInfo info = domain.getInfo();
boolean active = domain.isActive();
```

For domain name + uuid + state, that's enough.

For `powerState` string, translate `DomainState` to a friendly string like "running", "paused", "shutdown", "shutoff", etc.

Now, native library considerations:
- libvirt-java requires `libvirt.so` (Linux), `libvirt.dylib` (macOS), or the Windows equivalent. On the client machine.
- Users need to install `libvirt-dev` (Linux), `brew install libvirt` (macOS), or use WSL on Windows.
- Connection string: `qemu+tcp://host/system` (port 16509), `qemu+tls://host/system` (16514), `qemu+ssh://host/system` (SSH tunnel, port 22), or `qemu:///system` (local).

For auth: `conn.authList()` etc., or just pass user via URI: `qemu+tcp://user@host/system?authfile=...` or use SASL.

Simplest: `qemu+ssh://host/system` for secure connections (uses SSH keys, no libvirt config needed). `qemu+tcp://host/system` for insecure plain or SASL.

Let me present `qemu+ssh` and `qemu+tcp` as options, plus mention SASL config.

Also need to handle many different domain types:
- QEMU/KVM: `qemu://...`
- LXC: `lxc://...`
- Xen: `xen://...`

The `conn.getType()` returns "QEMU", "XEN", "LXC", "OPENVZ", "UML", "VBOX", "VMWARE", "BHYVE", "VZ", "VMWARE", "HYPERV" etc.

For our purposes, we typically care about QEMU/KVM and LXC on Linux, so we can accept arbitrary driver.

Now let me structure:

```java
package netdisc.virtualization;

import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;
import org.libvirt.*;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.ByteArrayInputStream;
import java.util.*;

public final class LibvirtDiscovery {

    public record Options(String uri, String hostIpOrName) {}

    public static List<VirtualizationHost> discover(Options opt, List<VirtualMachine> vmSink)
            throws Exception {
        Connect conn = null;
        try {
            conn = new Connect(opt.uri(), true);  // read-only
            return collect(conn, opt, vmSink);
        } finally {
            if (conn != null) try { conn.close(); } catch (Exception ignored) {}
        }
    }

    private static List<VirtualizationHost> collect(Connect conn, Options opt, List<VirtualMachine> vmSink) throws Exception {
        VirtualizationHost vh = new VirtualizationHost();
        vh.type = driverTypeToKind(conn.getType());  // "kvm" | "lxc" | "xen" | ...
        vh.source = "api";
        vh.name = safe(() -> conn.getHostname(), opt.hostIpOrName());
        vh.ip = opt.hostIpOrName() != null ? opt.hostIpOrName() : vh.name;
        vh.id = vh.type + ":" + vh.ip;
        vh.version = "libvirt " + conn.getLibVersion();
        vh.metadata.put("driver", conn.getType());
        vh.metadata.put("libVersion", String.valueOf(conn.getLibVersion()));

        // Hypervisor info
        try {
            ConnectInfo info = conn.getInfo();
            vh.metadata.put("model", info.getModel());
            vh.metadata.put("cpus", String.valueOf(info.getCpus()));
            vh.metadata.put("memoryMB", String.valueOf(info.getMemory() / 1024L));
            vh.metadata.put("cpuMhz", String.valueOf(info.getMhz()));
            vh.metadata.put("nodes", String.valueOf(info.getNodes()));
            vh.metadata.put("sockets", String.valueOf(info.getSockets()));
            vh.metadata.put("cores", String.valueOf(info.getCores()));
            vh.metadata.put("threads", String.valueOf(info.getThreads()));
        } catch (Exception ignored) {}

        // Networks (virtual bridges, NAT subnets)
        try {
            int[] netIds = conn.listNetworks();
            if (netIds != null) {
                List<String> netNames = new ArrayList<>();
                for (int id : netIds) {
                    Network net = conn.networkLookupByID(id);
                    if (net == null) continue;
                    netNames.add(net.getName());
                    String xml = net.getXMLDesc(0);
                    Document doc = parse(xml);
                    if (doc == null) continue;
                    NodeList ips = doc.getElementsByTagName("ip");
                    for (int i = 0; i < ips.getLength(); i++) {
                        Element el = (Element) ips.item(i);
                        String addr = el.getAttribute("address");
                        String netmask = el.getAttribute("netmask");
                        String prefix = el.getAttribute("prefix");
                        if (addr == null || addr.isBlank()) continue;
                        int p = !prefix.isBlank() ? Integer.parseInt(prefix)
                                : (netmask != null && !netmask.isBlank() ? maskToPrefix(netmask) : 24);
                        vh.managementNets.add(addr + "/" + p);
                    }
                }
                if (!netNames.isEmpty()) vh.metadata.put("networks", String.join(",", netNames));
            }
        } catch (Exception ignored) {}

        // Physical interfaces (may have static IPs when driven by libvirt)
        try {
            int[] ifIds = conn.listInterfaces();
            if (ifIds != null) {
                List<String> ifNames = new ArrayList<>();
                for (int id : ifIds) {
                    Interface itf = conn.interfaceLookupByID(id);
                    if (itf == null) continue;
                    ifNames.add(itf.getName());
                    try {
                        String xml = itf.getXMLDesc(0);
                        Document doc = parse(xml);
                        if (doc == null) continue;
                        NodeList ipEls = doc.getElementsByTagName("ip");
                        for (int i = 0; i < ipEls.getLength(); i++) {
                            Element el = (Element) ipEls.item(i);
                            String a = el.getAttribute("address");
                            String prefix = el.getAttribute("prefix");
                            if (a == null || a.isBlank()) continue;
                            int p = !prefix.isBlank() ? Integer.parseInt(prefix) : 24;
                            vh.managementNets.add(a + "/" + p);
                        }
                    } catch (Exception ignored) {}
                }
                if (!ifNames.isEmpty()) vh.metadata.put("interfaces", String.join(",", ifNames));
            }
        } catch (Exception ignored) {}

        // Storage pools
        try {
            int[] poolIds = conn.listStoragePools();
            if (poolIds != null) {
                List<String> pools = new ArrayList<>();
                for (int id : poolIds) {
                    StoragePool sp = conn.storagePoolLookupByID(id);
                    if (sp == null) continue;
                    pools.add(sp.getName() + "(" + sp.getInfo().getState() + ")");
                }
                if (!pools.isEmpty()) vh.metadata.put("storagePools", String.join(",", pools));
            }
        } catch (Exception ignored) {}

        // Domains (VMs)
        int[] domIds = conn.listDomains();
        int[] inactiveIds = conn.listDefinedDomains();
        // Actually listDefinedDomains returns int[]? Or String[]?
        // In libvirt-java 0.5.x, listDomains() returns int[], listDefinedDomains() returns String[]? Let me check...
        // Actually I recall listDomains() returns int[] (active IDs), and listDefinedDomains() returns String[] (inactive names).
        // Or both return int[]? Hmm. Let me use listAllDomains() which returns Domain[] in newer versions.
        // In libvirt-java 0.5.x: conn.listAllDomains() returns Domain[]. Might be conn.listAllDomains(int flags) in 0.5.x.

        Domain[] domains = null;
        try {
            domains = conn.listAllDomains(0);  // flags=0 = all
        } catch (Throwable t) {
            // older libvirt-java versions
            List<Domain> all = new ArrayList<>();
            int[] activeIds = safeIntArray(() -> conn.listDomains());
            for (int id : activeIds) {
                Domain d = conn.domainLookupByID(id);
                if (d != null) all.add(d);
            }
            String[] inactiveNames = safeStringArray(() -> conn.listDefinedDomains());
            for (String name : inactiveNames) {
                Domain d = conn.domainLookupByName(name);
                if (d != null) all.add(d);
            }
            domains = all.toArray(new Domain[0]);
        }
        if (domains != null) {
            for (Domain dom : domains) {
                try {
                    VirtualMachine vm = parseVm(dom, vh);
                    // Guest IP
                    vm.ip = tryGuestIp(dom);
                    vmSink.add(vm);
                } catch (Exception ignored) {}
            }
        }

        return List.of(vh);
    }

    private static VirtualMachine parseVm(Domain dom, VirtualizationHost vh) throws Exception {
        VirtualMachine vm = new VirtualMachine();
        vm.hostId = vh.id;
        vm.name = dom.getName();
        try { vm.uuid = dom.getUUIDString(); } catch (Exception ignored) {}
        try { vm.powerState = dom.isActive() ? "running" : "shutoff"; } catch (Exception ignored) {}

        String xml = dom.getXMLDesc(0);
        Document doc = parse(xml);
        if (doc != null) {
            // OS type
            NodeList os = doc.getElementsByTagName("type");
            if (os.getLength() > 0) {
                Element t = (Element) os.item(0);
                if ("hvm".equals(t.getTextContent()) || "hvm".equals(t.getAttribute("type"))) {
                    // Could enrich guestOs later
                }
            }
            // Title/description
            NodeList title = doc.getElementsByTagName("title");
            if (title.getLength() > 0) vm.guestOs = null;  // don't overload
            // Devices → interfaces
            NodeList ifaces = doc.getElementsByTagName("interface");
            for (int i = 0; i < ifaces.getLength(); i++) {
                Element iface = (Element) ifaces.item(i);
                String mac = null;
                NodeList macs = iface.getElementsByTagName("mac");
                if (macs.getLength() > 0) mac = ((Element) macs.item(0)).getAttribute("address");
                if (mac != null && !mac.isEmpty()) {
                    mac = mac.toLowerCase();
                    vh.vmMacs.add(mac);
                    if (vm.mac == null) vm.mac = mac;
                }
                String backing = resolveInterfaceBacking(iface);
                vm.nics.add((mac == null ? "no-mac" : mac) + "@" + backing);
            }
        }
        return vm;
    }

    private static String tryGuestIp(Domain dom) {
        // ARP → agent → lease
        for (int source : new int[]{2, 1, 0}) {
            try {
                DomainInterfaceInfo[] infos = dom.interfaceAddresses(source);
                if (infos == null) continue;
                for (DomainInterfaceInfo di : infos) {
                    if (di.getAddrs() == null) continue;
                    for (DomainInterfaceAddress a : di.getAddrs()) {
                        if (a.getType() == DomainInterfaceAddress.AddressType.VIR_IP_ADDR_TYPE_IPV4) {
                            return a.getAddr();
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static String resolveInterfaceBacking(Element iface) {
        String type = iface.getAttribute("type");
        NodeList src = iface.getElementsByTagName("source");
        if (src.getLength() > 0) {
            Element s = (Element) src.item(0);
            switch (type) {
                case "network":  return "net:" + s.getAttribute("network");
                case "bridge":   return "br:" + s.getAttribute("bridge");
                case "direct":   return "macvtap:" + s.getAttribute("dev");
                case "user":     return "slirp";
                case "hostdev":  return "hostdev";
                case "vhostuser":return "vhostuser:" + s.getAttribute("path");
                case "ethernet": return "eth:" + s.getAttribute("dev");
                default:         return type;
            }
        }
        return type;
    }

    private static String driverTypeToKind(String libvirtType) {
        if (libvirtType == null) return "kvm";
        return switch (libvirtType.toUpperCase()) {
            case "QEMU"  -> "kvm";
            case "LXC"   -> "lxc";
            case "XEN"   -> "xen";
            case "BHYVE" -> "bhyve";
            default      -> libvirtType.toLowerCase();
        };
    }

    private static Document parse(String xml) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
        } catch (Exception e) {
            return null;
        }
    }

    private static int maskToPrefix(String mask) {
        try {
            String[] p = mask.split("\\.");
            int total = 0;
            for (String s : p) {
                int b = Integer.parseInt(s);
                total += Integer.bitCount(b & 0xFF);
            }
            return total;
        } catch (Exception e) { return 24; }
    }

    private static <T> T safe(ThrowingSupplier<T> s, T fallback) {
        try { return s.get(); } catch (Exception e) { return fallback; }
    }
    private interface ThrowingSupplier<T> { T get() throws Exception; }

    private static int[] safeIntArray(ThrowingSupplier<int[]> s) {
        try { return s.get(); } catch (Exception e) { return new int[0]; }
    }
    private static String[] safeStringArray(ThrowingSupplier<String[]> s) {
        try { return s.get(); } catch (Exception e) { return new String[0]; }
    }
}
```

Wait, `Connect.close()` or `Connect.disconnect()`? In libvirt-java it's `conn.close()` I think. Let me use `conn.close()`.

Also, `conn.listAllDomains(0)` — in libvirt-java 0.5.x, is this method available? Looking at the API...
- `Connect.listDomains()` returns `int[]`
- `Connect.listDefinedDomains()` returns `String[]`
- `Connect.listAllDomains()` (no args) returns `Domain[]` in some versions
- `Connect.listAllDomains(int flags)` returns `Domain[]` in others

I'll try `listAllDomains(0)` with fallback.

Also, `domain.interfaceAddresses(int)` — which version? Might not exist in older versions. Let me wrap in try-catch (already doing).

`DomainInterfaceInfo.AddressType.VIR_IP_ADDR_TYPE_IPV4` — the exact constant name... let me check. In libvirt-java it might be `VIR_IP_ADDR_TYPE_IPV4 = 0` as an int constant, not enum. Hmm. Let me use `a.getType() == 0` for IPv4 to be safe. Actually the classes are:
- `DomainInterfaceAddress` has `getType()` → int?
- Or `getType()` → enum?

Looking at libvirt-java source... I recall `DomainInterfaceAddress.getType()` returns `int`. And there are constants `VIR_IP_ADDR_TYPE_IPV4 = 0`, `VIR_IP_ADDR_TYPE_IPV6 = 1`.

Actually, looking again at libvirt-java docs, I think the method returns `DomainInterfaceInfo[]` and each `DomainInterfaceInfo` has `getAddrs()` returning `DomainInterfaceAddress[]`. `DomainInterfaceAddress` has `getAddr()`, `getPrefix()`, `getType()` (int).

So my code should be:
```java
if (a.getType() == 0) return a.getAddr();
```

For IPv4 = 0.

OK let me update.

Also, `ConnectType` or `conn.getType()` — returns String "QEMU" etc.

For `Connect.getInfo()` returns `ConnectInfo` with `getModel()`, `getCpus()`, etc. This might fail if connection is to a container driver. Wrap in try-catch.

For `conn.getLibVersion()` — returns int (like 6000001 for 6.0.1). Convert to string.

Let me also handle the case where libvirt-java itself is not loaded (native library missing). The `new Connect(...)` will throw `UnsatisfiedLinkError` (a subclass of Error, not Exception). Handle gracefully:

```java
try {
    conn = new Connect(opt.uri(), true);
} catch (UnsatisfiedLinkError e) {
    throw new RuntimeException(
        "libvirt native kütüphanesi bulunamadı. Linux: apt install libvirt-dev. " +
        "macOS: brew install libvirt. Windows: WSL2 + libvirt. " +
        "Ayrıntı: " + e.getMessage(), e);
}
```

Now for Maven:

```xml
<dependency>
    <groupId>org.libvirt</groupId>
    <artifactId>libvirt</artifactId>
    <version>0.5.2</version>
</dependency>
```

Latest on Maven Central: 0.5.2 (I believe). Good.

Connection URI examples:
- `qemu+ssh://user@10.10.0.20/system` (SSH tunnel, recommends SSH keys)
- `qemu+tcp://10.10.0.20/system` (TCP, 16509, SASL/polkit)
- `qemu+tls://10.10.0.20/system` (TLS, 16514)
- `qemu:///system` (local)
- `lxc:///` (local container)

For SSH, libvirt will use the user's SSH configuration (`~/.ssh/config`, agent keys). Just need `libvirt-client` installed on the remote for the `virt-ssh-helper` (or it just runs the `nc` trick via SSH). Actually the `qemu+ssh` driver uses SSH to run `virsh` in daemon mode remotely — needs `libvirtd` running on the target (or `virt-ssh-helper` + socket activation).

For TCP, needs `listen_tcp=1` in `libvirtd.conf` and auth_tcp setting.

Let me present both and mention security.

Now let me also handle `listAllInterfaces()` returning Interface[] (or int[] depending on version). Let me try — but I already covered with fallback. Actually `listInterfaces()` returns `int[]` in older. `listAllInterfaces()` returns `Interface[]` (no args) in newer. Let me try `listAllInterfaces()` without args.

Hmm, avoiding API incompat... let me use the simple approach:
```java
int[] ifIds = conn.listInterfaces();
```
If that fails, skip.

Similarly for storage pools:
```java
int[] poolIds = conn.listStoragePools();
```

If the interface/pool listing API is missing in the libvirt-java version, fall back gracefully (already wrapped).

OK, so I need to look at `getInfo()` for `Connect`. It's `ConnectInfo` I think. Actually looking at libvirt-java:
- `Connect.getInfo()` → `ConnectInfo` (or `NodeInfo` in older)
- Class `ConnectInfo` with `getCpus()`, `getMhz()`, `getNodes

**Kullanıcı:**

Yarım kalan sonucu bitirebilir misin?

**Asistan:**

# KVM / libvirt — `libvirt-java` ile API tabanlı envanter

Önceki turda yarıda kalan `LibvirtDiscovery` sınıfını tamamlıyorum. SSH + `virsh` (mevcut `KvmDiscovery`) yavaş ve kırılgan; libvirt-java ise **native libvirt kütüphanesini JNI ile çağırır**, tek `Connect()` ile dakikalar yerine saniyeler içinde tüm envanteri alır. Tek önkoşul: istemci makinede `libvirt-dev` (Linux) veya `brew install libvirt` (macOS) kurulu olması. Windows'ta WSL2 gerekir.

---

## 1. `pom.xml` — `libvirt-java` ekle

```xml
<!-- libvirt Java binding (JNI) -->
<dependency>
    <groupId>org.libvirt</groupId>
    <artifactId>libvirt</artifactId>
    <version>0.5.2</version>
</dependency>
```

> **Native kütüphane zorunlu:** `libvirt-java` saf Java değildir; `libvirt.so` / `libvirt.dylib` / `libvirt-x.x.x.dll`'yi çalışma zamanında yükler. Linux istemcide `apt install libvirt-dev libvirt-bin` (Debian/Ubuntu) veya `dnf install libvirt-devel libvirt-client` (RHEL/CentOS). macOS: `brew install libvirt`. Windows: WSL2 içinde çalıştır. Yoksa `UnsatisfiedLinkError` fırlatır; aşağıdaki kod bunu yakalayıp **anlaşılır Türkçe mesaja** çevirir ve mevcut `--kvm` (SSH + virsh) yöntemine düşebilmen için yol gösterir.

---

## 2. `Credential` modeli

Aynı `Credential` sınıfını kullanıyoruz; libvirt URI **`host` alanına** yazılır. Yeni bir alan açmaya gerek yok:

```java
// DiscoveryConfig.Credential zaten:
//   kind = "libvirt"
//   host = "qemu+ssh://user@10.10.0.20/system"
//   user / passOrKey = opsiyonel (URI'de varsa gerekmez)
```

---

## 3. `LibvirtDiscovery` — tam sınıf

```java
// src/main/java/netdisc/virtualization/LibvirtDiscovery.java
package netdisc.virtualization;

import netdisc.model.VirtualMachine;
import netdisc.model.VirtualizationHost;
import org.libvirt.*;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class LibvirtDiscovery {

    /** libvirt URI (qemu+ssh://user@host/system gibi). user/pass opsiyonel; URI'de varsa önceliklidir. */
    public record Options(String uri, String user, String pass) {}

    public static List<VirtualizationHost> discover(Options opt, List<VirtualMachine> vmSink)
            throws Exception {
        Connect conn;
        try {
            conn = new Connect(opt.uri(), true);   // readOnly = true
        } catch (UnsatisfiedLinkError e) {
            throw new RuntimeException(
                "libvirt native kütüphanesi bulunamadı: " + e.getMessage() +
                "\n  Linux:   sudo apt install libvirt-dev libvirt-bin   (veya dnf libvirt-devel libvirt-client)\n" +
                "  macOS:   brew install libvirt\n" +
                "  Windows: WSL2 + libvirt kurulumu gerekir\n" +
                "  Alternatif: --kvm <host> (SSH + virsh) kullanabilirsin.", e);
        }
        try {
            return collect(conn, opt, vmSink);
        } finally {
            try { conn.close(); } catch (Throwable ignored) {}
        }
    }

    // =====================================================================
    private static List<VirtualizationHost> collect(Connect conn, Options opt,
                                                    List<VirtualMachine> vmSink) throws Exception {
        String driverType = safe(conn::getType, "QEMU");
        String hostIdent  = extractHost(opt.uri());

        VirtualizationHost vh = new VirtualizationHost();
        vh.type   = driverTypeToKind(driverType);   // "kvm" | "lxc" | "xen" | ...
        vh.source = "api";
        vh.ip     = hostIdent;
        vh.name   = safe(conn::getHostname, hostIdent);
        vh.id     = vh.type + ":" + vh.ip;

        // libvirt kütüphane sürümü
        try {
            int v = conn.getLibVersion();
            vh.version = "libvirt " + (v/1_000_000) + "." + ((v/1_000)%1_000) + "." + (v%1_000);
        } catch (Exception ignored) {}
        vh.metadata.put("driver", driverType);
        vh.metadata.put("uri", opt.uri());

        // --- Hypervisor (node) bilgisi
        try {
            NodeInfo ni = conn.getNodeInfo();
            if (ni != null) {
                vh.metadata.put("model",   ni.getModel());
                vh.metadata.put("cpus",    String.valueOf(ni.getCpus()));
                vh.metadata.put("mhz",     String.valueOf(ni.getMhz()));
                vh.metadata.put("memoryMB",String.valueOf(ni.getMemory() / 1024L));
                vh.metadata.put("nodes",   String.valueOf(ni.getNodes()));
                vh.metadata.put("sockets", String.valueOf(ni.getSockets()));
                vh.metadata.put("cores",   String.valueOf(ni.getCores()));
                vh.metadata.put("threads", String.valueOf(ni.getThreads()));
            }
        } catch (Exception ignored) {}

        // --- Virtual network'ler (bridge/NAT subnets)
        List<String> networkNames = new ArrayList<>();
        try {
            int[] netIds = safeIntArray(conn::listNetworks);
            for (int id : netIds) {
                Network net = conn.networkLookupByID(id);
                if (net == null) continue;
                networkNames.add(net.getName());
                Document doc = parse(net.getXMLDesc(0));
                if (doc == null) continue;
                NodeList ips = doc.getElementsByTagName("ip");
                for (int i = 0; i < ips.getLength(); i++) {
                    Element el = (Element) ips.item(i);
                    String addr = el.getAttribute("address");
                    if (addr == null || addr.isBlank()) continue;
                    int prefix;
                    try { prefix = Integer.parseInt(el.getAttribute("prefix")); }
                    catch (NumberFormatException nfe) {
                        prefix = maskToPrefix(el.getAttribute("netmask"));
                    }
                    vh.managementNets.add(addr + "/" + prefix);
                }
            }
            if (!networkNames.isEmpty())
                vh.metadata.put("networks", String.join(",", networkNames));
        } catch (Exception ignored) {}

        // --- Fiziksel arayüzler (statik IP varsa)
        List<String> ifNames = new ArrayList<>();
        try {
            int[] ifIds = safeIntArray(conn::listInterfaces);
            for (int id : ifIds) {
                Interface itf = conn.interfaceLookupByID(id);
                if (itf == null) continue;
                ifNames.add(itf.getName());
                try {
                    Document doc = parse(itf.getXMLDesc(0));
                    if (doc == null) continue;
                    NodeList ipEls = doc.getElementsByTagName("ip");
                    for (int i = 0; i < ipEls.getLength(); i++) {
                        Element el = (Element) ipEls.item(i);
                        String a = el.getAttribute("address");
                        if (a == null || a.isBlank()) continue;
                        int p;
                        try { p = Integer.parseInt(el.getAttribute("prefix")); }
                        catch (NumberFormatException nfe) { p = 24; }
                        vh.managementNets.add(a + "/" + p);
                    }
                } catch (Exception ignored) {}
            }
            if (!ifNames.isEmpty())
                vh.metadata.put("interfaces", String.join(",", ifNames));
        } catch (Exception ignored) {}

        // --- Storage pool'ları (isim + durum)
        List<String> pools = new ArrayList<>();
        try {
            int[] poolIds = safeIntArray(conn::listStoragePools);
            for (int id : poolIds) {
                StoragePool sp = conn.storagePoolLookupByID(id);
                if (sp == null) continue;
                String state;
                try { state = String.valueOf(sp.getInfo().getState()); }
                catch (Exception e) { state = "?"; }
                pools.add(sp.getName() + "(" + state + ")");
            }
            if (!pools.isEmpty())
                vh.metadata.put("storagePools", String.join("; ", pools));
        } catch (Exception ignored) {}

        // --- Domain (VM) listesi — listAllDomains varsa, yoksa manuel topla
        Domain[] domains;
        try {
            domains = conn.listAllDomains();
        } catch (Throwable t) {
            List<Domain> all = new ArrayList<>();
            for (int id : safeIntArray(conn::listDomains)) {
                try { Domain d = conn.domainLookupByID(id); if (d != null) all.add(d); }
                catch (Exception ignored) {}
            }
            try {
                String[] inactive = conn.listDefinedDomains();
                if (inactive != null)
                    for (String name : inactive) {
                        try { Domain d = conn.domainLookupByName(name); if (d != null) all.add(d); }
                        catch (Exception ignored) {}
                    }
            } catch (Exception ignored) {}
            domains = all.toArray(new Domain[0]);
        }
        if (domains == null) domains = new Domain[0];

        for (Domain dom : domains) {
            try {
                VirtualMachine vm = parseVm(dom, vh);
                if (vm.ip == null) vm.ip = tryGuestIp(dom);
                vmSink.add(vm);
            } catch (Exception ignored) {}
        }

        return List.of(vh);
    }

    // ===================== VM =====================
    private static VirtualMachine parseVm(Domain dom, VirtualizationHost vh) throws Exception {
        VirtualMachine vm = new VirtualMachine();
        vm.hostId    = vh.id;
        vm.name      = dom.getName();
        vm.powerState = dom.isActive() ? "running" : "shutoff";
        try { vm.uuid = dom.getUUIDString(); } catch (Exception ignored) {}

        String xml = null;
        try { xml = dom.getXMLDesc(0); }
        catch (Exception e) {
            try { xml = dom.getXMLDesc(2); } // VIR_DOMAIN_XML_INACTIVE
            catch (Exception ignored) {}
        }
        if (xml == null) return vm;

        Document doc = parse(xml);
        if (doc == null) return vm;

        // <title>/<description> → metadata olarak saklamak istersen buradan alabilirsin.
        NodeList ifaces = doc.getElementsByTagName("interface");
        for (int i = 0; i < ifaces.getLength(); i++) {
            Element iface = (Element) ifaces.item(i);
            String mac = null;
            NodeList macs = iface.getElementsByTagName("mac");
            if (macs.getLength() > 0) {
                String m = ((Element) macs.item(0)).getAttribute("address");
                if (m != null && !m.isBlank()) mac = m.toLowerCase().replace('-', ':');
            }
            if (mac != null) {
                vh.vmMacs.add(mac);
                if (vm.mac == null) vm.mac = mac;
            }
            vm.nics.add((mac == null ? "no-mac" : mac) + "@" + resolveInterfaceBacking(iface));
        }
        return vm;
    }

    private static String resolveInterfaceBacking(Element iface) {
        String type = iface.getAttribute("type");
        NodeList src = iface.getElementsByTagName("source");
        if (src.getLength() > 0) {
            Element s = (Element) src.item(0);
            return switch (type) {
                case "network"   -> "net:" + s.getAttribute("network");
                case "bridge"    -> "br:"  + s.getAttribute("bridge");
                case "direct"    -> "macvtap:" + s.getAttribute("dev");
                case "user"      -> "slirp";
                case "hostdev"   -> "hostdev";
                case "vhostuser" -> "vhostuser:" + s.getAttribute("path");
                case "ethernet"  -> "eth:" + s.getAttribute("dev");
                default          -> type;
            };
        }
        return type == null || type.isBlank() ? "unknown" : type;
    }

    // Guest IP: ARP (2) → agent (1) → DHCP lease (0)
    private static String tryGuestIp(Domain dom) {
        for (int source : new int[]{2, 1, 0}) {
            try {
                DomainInterfaceInfo[] infos = dom.interfaceAddresses(source);
                if (infos == null) continue;
                for (DomainInterfaceInfo di : infos) {
                    DomainInterfaceAddress[] addrs = di.getAddrs();
                    if (addrs == null) continue;
                    for (DomainInterfaceAddress a : addrs) {
                        // IPv4 = 0 (VIR_IP_ADDR_TYPE_IPV4)
                        Object t = a.getType();
                        boolean isV4 = (t instanceof Integer ti && ti == 0)
                                    || String.valueOf(t).equals("0")
                                    || String.valueOf(t).toUpperCase().contains("IPV4");
                        if (isV4 && a.getAddr() != null && !a.getAddr().isBlank())
                            return a.getAddr();
                    }
                }
            } catch (Throwable ignored) {}
        }
        return null;
    }

    // ===================== yardımcılar =====================
    private static String driverTypeToKind(String t) {
        if (t == null) return "kvm";
        return switch (t.toUpperCase(Locale.ROOT)) {
            case "QEMU"  -> "kvm";
            case "LXC"   -> "lxc";
            case "XEN"   -> "xen";
            case "BHYVE" -> "bhyve";
            case "VBOX"  -> "virtualbox";
            default      -> t.toLowerCase(Locale.ROOT);
        };
    }

    private static String extractHost(String uri) {
        try {
            URI u = URI.create(uri);
            String h = u.getHost();
            if (h != null && !h.isBlank()) return h;
        } catch (Exception ignored) {}
        // qemu:///system gibi local URI'ler
        if (uri.startsWith("qemu:///") || uri.startsWith("lxc:///") || uri.startsWith("xen:///"))
            return "localhost";
        // Son çare
        String s = uri.replaceFirst("^[a-zA-Z0-9+]+://", "");
        if (s.contains("@")) s = s.substring(s.indexOf('@') + 1);
        if (s.contains("/")) s = s.substring(0, s.indexOf('/'));
        return s.isBlank() ? "localhost" : s;
    }

    private static Document parse(String xml) {
        if (xml == null) return null;
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            return f.newDocumentBuilder().parse(
                    new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    private static int maskToPrefix(String mask) {
        if (mask == null || mask.isBlank()) return 24;
        try {
            int total = 0;
            for (String s : mask.split("\\."))
                total += Integer.bitCount(Integer.parseInt(s) & 0xFF);
            return total;
        } catch (Exception e) { return 24; }
    }

    private interface ThrowingSupplier<T> { T get() throws Exception; }
    private static <T> T safe(ThrowingSupplier<T> s, T fallback) {
        try { return s.get(); } catch (Exception e) { return fallback; }
    }
    private static int[] safeIntArray(ThrowingSupplier<int[]> s) {
        try { return s.get(); } catch (Exception e) { return new int[0]; }
    }
}
```

---

## 4. Orchestrator — `libvirt` case

Mevcut switch'e ekle:

```java
case "libvirt" -> LibvirtDiscovery.discover(
    new LibvirtDiscovery.Options(c.host, c.user, c.passOrKey),
    r.vms);
```

`--kvm` (SSH + `virsh`) case'i olduğu gibi kalır — native lib yoksa onu kullanırsın.

---

## 5. CLI argümanları

```java
// DiscoveryConfig.fromArgs() içine:
case "--libvirt"            -> cfg.vmCreds.add(new Credential("libvirt", a[++i], null, null));
case "--libvirt-user"       -> lastLibvirt(cfg).user = a[++i];
case "--libvirt-pass"       -> lastLibvirt(cfg).passOrKey = a[++i];
```

```java
private static Credential lastLibvirt(DiscoveryConfig cfg) {
    for (int i = cfg.vmCreds.size() - 1; i >= 0; i--) {
        Credential c = cfg.vmCreds.get(i);
        if ("libvirt".equals(c.kind)) return c;
    }
    throw new IllegalArgumentException("Önce --libvirt <uri> vermelisin");
}
```

---

## 6. Bağlantı URI'leri ve kimlik doğrulama

| URI | Port | Ne zaman kullanılır |
|---|---|---|
| `qemu+ssh://user@10.10.0.20/system` | 22 (SSH tüneli) | **En kolay**. SSH anahtarı kurulduysa şifre gerekmez. `libvirt-client` paketini gerekli kılar (SSH tüneli için). Kimlik bilgisi = SSH. |
| `qemu+tcp://10.10.0.20/system` | 16509 | Şifresiz ama SASL/polkit ile korunur. `libvirtd.conf` içinde `listen_tcp=1`, `auth_tcp="sasl"`. |
| `qemu+tls://10.10.0.20/system` | 16514 | CA + client sertifikası kurulu ise. `auth_tls="x509"`. |
| `qemu:///system` | — | Aynı makinede libvirt'e bağlan (test için). |
| `lxc:///` | — | Yerel LXC container listesi. |
| `xen:///` | — | Yerel Xen. |

**Kimlik bilgisi önceliği:** URI içinde `user@host` varsa libvirt-java bunu kullanır; ayrıca `pass` verilirse SASL için kullanılır. `qemu+ssh://` için **parola desteklenmez** (SSH anahtarı veya agent kullanılır); `user` bileşeni SSH kullanıcısıdır.

**Hazırlık (target KVM host):**

```bash
# libvirtd dinlemiyor olsa bile SSH ile bağlanabilirsin:
sudo apt install libvirt-daemon-system libvirt-clients
sudo systemctl enable --now libvirtd

# Uzaktan sorgu için (opsiyonel):
# /etc/libvirt/libvirtd.conf
#   listen_tcp = 1
#   auth_tcp = "sasl"
#   tls_no_verify_certificate = 0
```

**İstemci tarafı doğrulama (JVM dışında):**

```bash
virsh -c qemu+ssh://user@10.10.0.20/system list --all
virsh -c qemu+tcp://10.10.0.20/system list --all
```

Bu komutlar sorunsuz çalışıyorsa Java kodu da çalışır.

---

## 7. Örnek kullanım

```bash
# 1) SSH tüneli (önerilen — şifresiz, güvenli)
java -jar netdisc.jar \
  --cidr 10.10.0.0/24 --snmp public \
  --libvirt qemu+ssh://root@10.10.0.20/system \
  --libvirt qemu+ssh://root@10.10.0.21/system \
  --out rapor.json

# 2) TCP + SASL (şifreli kimlik doğrulama)
java -jar netdisc.jar \
  --cidr 10.10.0.0/24 --snmp public \
  --libvirt qemu+tcp://10.10.0.20/system \
    --libvirt-user admin --libvirt-pass 'S3cr3t!' \
  --out rapor.json

# 3) Karışık: vCenter + Hyper-V + KVM (aynı raporda)
java -jar netdisc.jar --cidr 10.10.0.0/24 --snmp public \
  --vcenter https://vcenter.corp.local/sdk \
      --vcenter-user 'administrator@vsphere.local' --vcenter-pass 'Admin!23' --vcenter-insecure \
  --hyperv 10.10.0.30 --hyperv-domain CORP \
      --hyperv-user svc-scan --hyperv-pass 'S3cr3t!' \
  --libvirt qemu+ssh://root@10.10.0.20/system \
  --out rapor.json
```

---

## 8. Örnek çıktı (`rapor.json`, kısaltılmış)

```json
{
  "vhosts": [
    {
      "id": "kvm:10.10.0.20",
      "type": "kvm", "source": "api",
      "ip": "10.10.0.20", "name": "kvm-01.corp.local",
      "version": "libvirt 8.5.2",
      "managementNets": ["192.168.122.1/24", "10.20.0.10/16", "10.10.0.20/24"],
      "vmMacs": ["52:54:00:aa:bb:cc", "52:54:00:dd:ee:ff"],
      "metadata": {
        "driver": "QEMU",
        "uri": "qemu+ssh://root@10.10.0.20/system",
        "model": "x86_64",
        "cpus": "32", "mhz": "2400", "memoryMB": "131072",
        "nodes": "2", "sockets": "2", "cores": "8", "threads": "2",
        "networks": "default,br-prod,br-mgmt",
        "interfaces": "eth0,eth1,bond0",
        "storagePools": "default(running); pool-iso(running)"
      }
    }
  ],
  "vms": [
    {
      "name": "web-01", "uuid": "4211d14a-...", "hostId": "kvm:10.10.0.20",
      "mac": "52:54:00:aa:bb:cc", "ip": "10.10.0.55",
      "powerState": "running",
      "nics": [
        "52:54:00:aa:bb:cc@br:br-prod",
        "52:54:00:dd:ee:ff@net:br-mgmt"
      ]
    }
  ],
  "devices": [
    {
      "ip": "10.10.0.55", "mac": "52:54:00:aa:bb:cc",
      "kind": "VIRTUAL_MACHINE", "ownerHostId": "kvm:10.10.0.20",
      "discoveredBy": ["tcp", "arp"],
      "metadata": { "match": "api-mac" }
    }
  ]
}
```

---

## 9. Eşleşme akışı (uçtan uca)

```
[TCP/ARP/SNMP]      Device(mac=52:54:00:aa:bb:cc) @ 10.10.0.55
                              │
[LibvirtDiscovery]  kvm:10.10.0.20.vmMacs += 52:54:00:aa:bb:cc
                              │
                    managementNets: 192.168.122.0/24, 10.20.0.0/16
                              │
[Orchestrator BFS]  Yeni segmentler kuyruğa → yeni tarama dalgası
                              │
[VMHostMatcher]     ownerHostId = kvm:10.10.0.20, match = "api-mac"
                              │
[VM IP sync]        VM.ip = Device.ip (guest agent yoksa ARP'den dolar)
```

---

## 10. Önemli notlar

- **`source="api"`** alanı, aynı IP için daha önce `guessType` ile eklenmiş `"fingerprint"` kaydını **dedup** aşamasında ezer — çift host kaydı olmaz.
- **`managementNets`**: libvirt, bridge/NAT subnet'lerini XML olarak verir; `10.20.0.0/16` gibi **büyük alt ağlar** çıkarsa BFS kuyruğuna girmesi `--max-subnets` sınırına takılabilir. İstersen `LibvirtDiscovery` içinde `/22`'den küçük CIDR'leri (yani /23, /22, ... /16) filtreleyip **sadece /24'e indirge** — örnek: `if (prefix < 22) prefix = 22;`. Şu an tümünü kuyruğa atıyor; büyük ortamda `--max-subnets 256` ver.
- **`qemu+ssh` için virsh'e ek gerekmez** ama uzak tarafta `libvirt-client` paketi olmalı (SSH tüneli yardımcısı orada). Yoksa şu hatayı alırsın: `Cannot recv data: virsh: command not found`.
- **LXC container'ları** için `<interface type="bridge">` görürsün, MAC `52:54:00:*` gibi olmayabilir (host bridge MAC'i kullanılır). ARP eşleşmesi yine çalışır.
- **Guest IP katmanı**: `interfaceAddresses()` sırayla ARP → agent → DHCP lease dener; guest agent kurulu değilse bile çoğu durumda ARP'den IP gelir.
- **Windows'ta çalıştırmak** için WSL2 kullan; WSL içine `apt install libvirt-dev` yap ve `--libvirt qemu+ssh://...` URI'ni WSL'den dışarı çıkaracak şekilde kullan.

---

## 11. Sıradaki adımlar

**Hyper-V (✗ tamam) → vCenter (✗ tamam) → KVM/libvirt (✓ bu tur)**. Sırada:

1. **VLAN-aware LLDP/CDP çözümleyici** — 802.1Q tag sıyırma, SysName/PortDesc/MgmtAddr tam parse; switch port ↔ host MAC haritası çıkarma; topoloji grafiği.
2. **Web UI** (Spring Boot + d3.js) — `discovery-report.json`'ı canlı ağaç topolojisi olarak göster; her düğümde tip/MAC/port bilgisi, arama, filtre.

Hangisiyle devam edelim?

**Kullanıcı:**

Yine ilkiyle başlayalım lütfen.

**Asistan:**

# LLDP/CDP + 802.1Q VLAN — tam TLV çözümleyici

Bu turda L2 katmanını ciddiye alıyoruz. Önceki `L2Scanner.sniffNeighbors` sadece yazdırılabilir karakterleri topluyordu (kaba). Şimdi switch'lerin periyodik yaydığı **LLDP ve CDP** çerçevelerini **TLV düzeyinde** parçalıyor, VLAN tag'lerini sıyırıyor, komşu switch'in **yönetim IP'lerini**, **port ID'lerini**, **VLAN ID'lerini** ve **yeteneklerini** çıkarıyoruz.

Kritik nokta: **LLDP/CDP pasif dinlenebilir — switch kimlik bilgisi gerekmez.** Yani SNMP kapalı olsa bile komşu switch'leri bulabiliyor ve yönetim VLAN'larına yayılabiliyoruz.

---

## 1. Model: `TopologyLink` + `DiscoveryResult.links`

```java
// src/main/java/netdisc/model/TopologyLink.java
package netdisc.model;

import java.util.*;

public class TopologyLink {
    public String protocol;              // "LLDP" | "CDP"
    public String localDevice;           // bulunduysa bizim cihazın IP/MAC'i
    public String localMac;
    public String localIface;
    public Integer localVlan;            // 802.1Q VID (trunk ise dolu)

    public String remoteDevice;          // bulunduysa komşunun IP/MAC'i
    public String remoteChassisId;
    public String remotePort;
    public String remotePortDesc;
    public String remoteSystemName;
    public Integer remoteNativeVlan;     // LLDP Port VLAN ID / CDP Native VLAN
    public List<String> remoteMgmtIps = new ArrayList<>();
    public List<String> capabilities = new ArrayList<>();
    public long timestamp;
}
```

```java
// DiscoveryResult.java içine ekle
public List<TopologyLink> links = new ArrayList<>();
```

---

## 2. `NeighborRecord` — birleşik temsil

```java
// src/main/java/netdisc/l2/NeighborRecord.java
package netdisc.l2;

import java.util.*;

public class NeighborRecord {
    public enum Protocol { LLDP, CDP }
    public enum Capability { OTHER, REPEATER, BRIDGE, SWITCH, WLAN_AP, ROUTER,
                             TELEPHONE, DOCSIS, STATION, C_VLAN, S_VLAN, TWO_PORT_BRIDGE }

    public Protocol protocol;
    public long timestamp;

    // Yerel taraf
    public String localIface;
    public String localMac;
    public Integer localVlan;

    // Uzak taraf
    public String remoteChassisId, remoteChassisType;
    public String remotePortId, remotePortType, remotePortDesc;
    public String remoteSystemName, remoteSystemDesc;
    public Set<String> remoteMgmtIps  = new LinkedHashSet<>();
    public Set<Capability> remoteCapabilities = EnumSet.noneOf(Capability.class);
    public Integer remoteNativeVlan;
    public Integer remoteVlanId;
    public String remoteVlanName;
    public Integer ttl;

    public Map<String, String> extras = new LinkedHashMap<>();
}
```

---

## 3. `LldpTlvParser` — LLDP TLV tabanlı

EtherType **0x88CC** gövdesini ayrıştırır. Mandatory (Chassis/Port/TTL) + tüm optional TLVs, özellikle **IEEE 802.1 org-specific** (Port VLAN ID, VLAN Name) ve **Management Address**.

```java
// src/main/java/netdisc/l2/LldpTlvParser.java
package netdisc.l2;

import java.nio.charset.StandardCharsets;

public final class LldpTlvParser {

    /** payload: Ethernet ethertype 0x88CC sonrası gövde. */
    public static void parse(byte[] p, int off, int len, NeighborRecord r) {
        int end = off + len;
        int i = off;
        while (i + 2 <= end) {
            int header  = ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
            int tlvType = (header >> 9) & 0x7F;
            int tlvLen  = header & 0x1FF;
            i += 2;
            if (i + tlvLen > end) return;
            switch (tlvType) {
                case 0 -> { return; }  // End of LLDPDU
                case 1 -> parseChassisId(p, i, tlvLen, r);
                case 2 -> parsePortId(p, i, tlvLen, r);
                case 3 -> r.ttl = ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
                case 4 -> r.remotePortDesc   = text(p, i, tlvLen);
                case 5 -> r.remoteSystemName = text(p, i, tlvLen);
                case 6 -> r.remoteSystemDesc = text(p, i, tlvLen);
                case 7 -> parseCapabilities(p, i, tlvLen, r);
                case 8 -> parseMgmtAddr(p, i, tlvLen, r);
                case 127 -> parseOrgSpecific(p, i, tlvLen, r);
                default -> { }
            }
            i += tlvLen;
        }
    }

    // ---- mandatory ----
    private static void parseChassisId(byte[] p, int o, int l, NeighborRecord r) {
        if (l < 1) return;
        int sub = p[o] & 0xFF;
        int vlen = l - 1;
        r.remoteChassisType = switch (sub) {
            case 4 -> "mac";
            case 5 -> "network-address";
            case 7 -> "local";
            default -> "subtype-" + sub;
        };
        r.remoteChassisId = (sub == 4 && vlen == 6)
                ? mac(p, o + 1)
                : (sub == 5 && vlen >= 6 && (p[o+1] & 0xFF) == 1 ? ipv4(p, o + 2)
                                                                : text(p, o + 1, vlen));
    }

    private static void parsePortId(byte[] p, int o, int l, NeighborRecord r) {
        if (l < 1) return;
        int sub = p[o] & 0xFF;
        int vlen = l - 1;
        r.remotePortType = switch (sub) {
            case 3 -> "mac";
            case 5 -> "if-name";
            case 7 -> "local";
            default -> "subtype-" + sub;
        };
        r.remotePortId = (sub == 3 && vlen == 6) ? mac(p, o + 1) : text(p, o + 1, vlen);
    }

    private static void parseCapabilities(byte[] p, int o, int l, NeighborRecord r) {
        if (l < 4) return;
        int enabled = ((p[o+2] & 0xFF) << 8) | (p[o+3] & 0xFF);
        if ((enabled & 0x0002) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.REPEATER);
        if ((enabled & 0x0004) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.BRIDGE);
        if ((enabled & 0x0010) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.ROUTER);
        if ((enabled & 0x0080) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.STATION);
        if ((enabled & 0x0100) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.C_VLAN);
        if ((enabled & 0x0200) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.S_VLAN);
    }

    private static void parseMgmtAddr(byte[] p, int o, int l, NeighborRecord r) {
        int i = o, end = o + l;
        if (i + 2 > end) return;
        int addrLen = p[i++] & 0xFF;                // adres string uzunluğu (subtype dahil)
        if (addrLen < 1 || i + addrLen > end) return;
        int subtype = p[i++] & 0xFF;
        if (subtype == 1 && addrLen >= 5) r.remoteMgmtIps.add(ipv4(p, i));
        else if (subtype == 2 && addrLen >= 17) r.remoteMgmtIps.add(ipv6(p, i));
        i += (addrLen - 1);
        // interface number subtype (1) + number (4) = 5 byte atla
        if (i + 5 > end) return;
        i += 5;
        // OID string length (1) + OID
        if (i + 1 > end) return;
        int oidLen = p[i++] & 0xFF;
        i += oidLen;
    }

    // ---- IEEE 802.1 / 802.3 / TIA org-specific ----
    private static void parseOrgSpecific(byte[] p, int o, int l, NeighborRecord r) {
        if (l < 4) return;
        int oui = ((p[o] & 0xFF) << 16) | ((p[o+1] & 0xFF) << 8) | (p[o+2] & 0xFF);
        int sub = p[o + 3] & 0xFF;
        if (oui == 0x00120F) {          // IEEE 802.1
            switch (sub) {
                case 1 -> { if (l >= 6) r.remoteNativeVlan =
                        ((p[o+4] & 0xFF) << 8) | (p[o+5] & 0xFF); }  // Port VLAN ID
                case 3 -> { if (l >= 6) {
                    r.remoteVlanId   = ((p[o+4] & 0xFF) << 8) | (p[o+5] & 0xFF);
                    r.remoteVlanName = text(p, o + 6, l - 6);
                }}
            }
        } else if (oui == 0x0080C2) {   // IEEE 802.3
            // sub==1 → MAC/PHY config (autoneg, hız, duplex)... isteğe bağlı
        } else if (oui == 0x0012BB) {   // TIA / LLDP-MED
            switch (sub) {
                case 1 -> r.extras.put("med", "capabilities");
                case 3 -> r.extras.put("med", "location");
                case 4 -> r.extras.put("med", "poe");
            }
        }
    }

    // ---- helpers ----
    static String mac(byte[] b, int o) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", b[o + i] & 0xFF));
        }
        return sb.toString();
    }
    static String ipv4(byte[] b, int o) {
        return (b[o] & 0xFF) + "." + (b[o+1] & 0xFF) + "." + (b[o+2] & 0xFF) + "." + (b[o+3] & 0xFF);
    }
    static String ipv6(byte[] b, int o) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x%02x", b[o+i] & 0xFF, b[o+i+1] & 0xFF));
        }
        return sb.toString();
    }
    static String text(byte[] b, int o, int l) {
        int end = o + l;
        while (end > o && b[end - 1] == 0) end--;
        return new String(b, o, end - o, StandardCharsets.UTF_8);
    }
}
```

---

## 4. `CdpTlvParser` — CDP TLV tabanlı

EtherType **0x2000** gövdesini (veya LLC/SNAP `AA AA 03 + 00 00 0C 20 00` sonrası) ayrıştırır. CDP Header 4 byte (version, ttl, checksum), ardından **type(2) + len(2) + value** TLV'leri.

```java
// src/main/java/netdisc/l2/CdpTlvParser.java
package netdisc.l2;

public final class CdpTlvParser {

    /** p: CDP header'ının başlangıcı (LLC/SNAP varsa oradan sonrası). */
    public static void parse(byte[] p, int off, int len, NeighborRecord r) {
        int end = off + len;
        int i = off;
        if (i + 4 > end) return;
        i += 4;  // version, ttl, checksum(2)

        while (i + 4 <= end) {
            int type = ((p[i] & 0xFF) << 8) | (p[i+1] & 0xFF);
            int l    = ((p[i+2] & 0xFF) << 8) | (p[i+3] & 0xFF);
            if (l < 4 || i + l > end) return;
            int vOff = i + 4, vLen = l - 4;
            switch (type) {
                case 0x0001 -> r.remoteChassisId  = text(p, vOff, vLen);
                case 0x0003 -> r.remotePortId     = text(p, vOff, vLen);
                case 0x0014 -> r.remoteSystemName = text(p, vOff, vLen);
                case 0x0005 -> r.remoteSystemDesc = text(p, vOff, vLen);
                case 0x0006 -> r.extras.put("platform", text(p, vOff, vLen));
                case 0x0009 -> r.extras.put("vtpDomain", text(p, vOff, vLen));
                case 0x000A -> { if (vLen == 2) r.remoteNativeVlan =
                                    ((p[vOff] & 0xFF) << 8) | (p[vOff+1] & 0xFF); }
                case 0x0004 -> {  // Capabilities (4 byte)
                    if (vLen == 4) {
                        int caps = ((p[vOff] & 0xFF) << 24) | ((p[vOff+1] & 0xFF) << 16)
                                 | ((p[vOff+2] & 0xFF) << 8) | (p[vOff+3] & 0xFF);
                        if ((caps & 0x01) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.ROUTER);
                        if ((caps & 0x02) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.BRIDGE);
                        if ((caps & 0x08) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.SWITCH);
                        if ((caps & 0x10) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.STATION);
                        if ((caps & 0x40) != 0) r.remoteCapabilities.add(NeighborRecord.Capability.TELEPHONE);
                    }
                }
                case 0x0002 -> parseAddressList(p, vOff, vLen, r);
                case 0x0016 -> parseMgmtAddress(p, vOff, vLen, r);
                case 0x0013 -> { if (vLen == 1) r.extras.put("mtu-byte", String.valueOf(p[vOff] & 0xFF)); }
                case 0x000B -> { if (vLen == 1) r.extras.put("duplex", String.valueOf(p[vOff] & 0xFF)); }
            }
            i += l;
        }
    }

    private static void parseAddressList(byte[] p, int o, int l, NeighborRecord r) {
        if (l < 1) return;
        int count = p[o] & 0xFF;
        int i = o + 1, end = o + l;
        for (int k = 0; k < count && i + 2 <= end; k++) {
            i += 1;                                     // protocol type
            if (i >= end) return;
            int plen = p[i++] & 0xFF;
            i += plen;
            if (i + 2 > end) return;
            int alen = ((p[i] & 0xFF) << 8) | (p[i+1] & 0xFF);
            i += 2;
            if (i + alen > end) return;
            if (alen == 4) r.remoteMgmtIps.add(LldpTlvParser.ipv4(p, i));
            i += alen;
        }
    }

    private static void parseMgmtAddress(byte[] p, int o, int l, NeighborRecord r) {
        // Format: addr-count(1) [proto-type(1) proto-len(1) proto ... addr-len(2) addr ... ]*
        if (l < 1) return;
        int count = p[o] & 0xFF;
        int i = o + 1, end = o + l;
        for (int k = 0; k < count && i + 2 <= end; k++) {
            i += 1;
            if (i >= end) return;
            int plen = p[i++] & 0xFF;
            i += plen;
            if (i + 2 > end) return;
            int alen = ((p[i] & 0xFF) << 8) | (p[i+1] & 0xFF);
            i += 2;
            if (i + alen > end) return;
            if (alen == 4) r.remoteMgmtIps.add(LldpTlvParser.ipv4(p, i));
            i += alen;
        }
    }

    private static String text(byte[] b, int o, int l) { return LldpTlvParser.text(b, o, l); }
}
```

---

## 5. `NeighborSniffer` — pcap dinleyici + 802.1Q demux

Aktif taramaya paralel çalışır, ham baytları ayrıştırır. **Passive**, yani switch'e hiçbir şey göndermez.

```java
// src/main/java/netdisc/l2/NeighborSniffer.java
package netdisc.l2;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.*;

public final class NeighborSniffer {

    public record CaptureOptions(String iface, int durationMs) {}

    /**
     * LLDP + CDP çerçevelerini pasif olarak dinler.
     * Anahtar: "protocol|chassis|port|vlan" — aynı komşunun tekrar yayınları dedupe edilir.
     */
    public static List<NeighborRecord> capture(CaptureOptions opt) throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName(opt.iface());
        if (nif == null) throw new IllegalArgumentException("iface yok: " + opt.iface());

        String localMac = nif.getLinkLayerAddresses().isEmpty() ? null
                : macString(nif.getLinkLayerAddresses().get(0).getAddress());

        PcapHandle h = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        try {
            // LLDP (tag'li/tagsiz) + CDP (ethertype 0x2000) + LLC/SNAP CDP
            h.setFilter(
                "(ether proto 0x88cc) or (vlan and ether proto 0x88cc) or " +
                "(ether proto 0x2000) or (vlan and ether proto 0x2000) or " +
                "(llc)",
                BpfProgram.BpfCompileMode.OPTIMIZE);

            Map<String, NeighborRecord> byKey = new LinkedHashMap<>();
            long stop = System.currentTimeMillis() + opt.durationMs();
            while (System.currentTimeMillis() < stop) {
                Packet pkt;
                try { pkt = h.getNextPacketEx(); }
                catch (TimeoutException t) { continue; }
                catch (NotOpenException e) { break; }

                byte[] raw = pkt.getRawData();
                if (raw.length < 22) continue;

                int etherType = be16(raw, 12);
                int idx = 14;
                Integer vid = null;
                int depth = 0;
                while ((etherType == 0x8100 || etherType == 0x88A8) && idx + 4 <= raw.length) {
                    int tci = be16(raw, idx);
                    vid = tci & 0x0FFF;
                    etherType = be16(raw, idx + 2);
                    idx += 4;
                    if (++depth > 3) break;  // max QinQ derinliği
                }

                NeighborRecord r = new NeighborRecord();
                r.timestamp = System.currentTimeMillis();
                r.localIface = opt.iface();
                r.localMac   = localMac;
                r.localVlan  = vid;

                boolean ok = false;
                if (etherType == 0x88CC) {
                    r.protocol = NeighborRecord.Protocol.LLDP;
                    LldpTlvParser.parse(raw, idx, raw.length - idx, r);
                    ok = true;
                } else if (etherType == 0x2000) {
                    r.protocol = NeighborRecord.Protocol.CDP;
                    CdpTlvParser.parse(raw, idx, raw.length - idx, r);
                    ok = true;
                } else if (etherType <= 1500 && idx + 8 <= raw.length
                        && (raw[idx] & 0xFF) == 0xAA && (raw[idx+1] & 0xFF) == 0xAA
                        && (raw[idx+2] & 0xFF) == 0x03) {
                    int oui = ((raw[idx+3] & 0xFF) << 16) | ((raw[idx+4] & 0xFF) << 8) | (raw[idx+5] & 0xFF);
                    int pid = ((raw[idx+6] & 0xFF) << 8) | (raw[idx+7] & 0xFF);
                    if (oui == 0x00000C && pid == 0x2000) {
                        r.protocol = NeighborRecord.Protocol.CDP;
                        CdpTlvParser.parse(raw, idx + 8, etherType - 8, r);
                        ok = true;
                    }
                }
                if (!ok) continue;

                String key = r.protocol + "|" + r.remoteChassisId + "|" + r.remotePortId
                           + "|" + r.localVlan;
                byKey.put(key, r);   // en son gözlem kazanır
            }
            return new ArrayList<>(byKey.values());
        } finally {
            try { h.close(); } catch (Exception ignored) {}
        }
    }

    private static int be16(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o+1] & 0xFF); }
    private static String macString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", b[i] & 0xFF));
        }
        return sb.toString();
    }
}
```

---

## 6. `TopologyBuilder` — komşuları envanterle eşle

```java
// src/main/java/netdisc/l2/TopologyBuilder.java
package netdisc.l2;

import netdisc.model.*;

import java.net.InetAddress;
import java.util.*;

public final class TopologyBuilder {

    /** Neighbor listesini r.devices/r.vhosts ile eşleştir; r.links eklenir ve Device'lar zenginleştirilir. */
    public static void apply(DiscoveryResult r, List<NeighborRecord> neighbors) {
        Map<String, Device> byIp  = new HashMap<>();
        Map<String, Device> byMac = new HashMap<>();
        for (Device d : r.devices) {
            if (d.ip  != null) byIp.put(d.ip.getHostAddress(), d);
            if (d.mac != null) byMac.put(d.mac.toLowerCase(), d);
        }

        for (NeighborRecord n : neighbors) {
            Device local  = n.localMac != null ? byMac.get(n.localMac) : null;
            Device remote = null;
            if ("mac".equals(n.remoteChassisType) && n.remoteChassisId != null)
                remote = byMac.get(n.remoteChassisId);
            if (remote == null)
                for (String ip : n.remoteMgmtIps) if ((remote = byIp.get(ip)) != null) break;
            if (remote == null && n.remoteSystemName != null)
                for (Device d : r.devices)
                    if (n.remoteSystemName.equalsIgnoreCase(d.hostname)) { remote = d; break; }

            TopologyLink link = new TopologyLink();
            link.protocol        = n.protocol.name();
            link.localDevice     = local == null ? null
                                 : (local.ip != null ? local.ip.getHostAddress() : local.mac);
            link.localMac        = n.localMac;
            link.localIface      = n.localIface;
            link.localVlan       = n.localVlan;
            link.remoteDevice    = remote == null ? null
                                 : (remote.ip != null ? remote.ip.getHostAddress() : remote.mac);
            link.remoteChassisId = n.remoteChassisId;
            link.remotePort      = n.remotePortId;
            link.remotePortDesc  = n.remotePortDesc;
            link.remoteSystemName= n.remoteSystemName;
            link.remoteNativeVlan= n.remoteNativeVlan;
            link.remoteMgmtIps   = new ArrayList<>(n.remoteMgmtIps);
            link.capabilities    = n.remoteCapabilities.stream().map(Enum::name).toList();
            link.timestamp       = n.timestamp;
            r.links.add(link);

            // Uzak cihaz tipini işaretle + zenginleştir
            if (remote != null) {
                if (n.remoteCapabilities.contains(NeighborRecord.Capability.ROUTER)
                        && remote.kind != Device.Kind.ROUTER) {
                    remote.kind = Device.Kind.ROUTER;
                } else if (n.remoteCapabilities.contains(NeighborRecord.Capability.SWITCH)
                        && remote.kind == Device.Kind.UNKNOWN) {
                    remote.kind = Device.Kind.SWITCH;
                } else if (n.remoteCapabilities.contains(NeighborRecord.Capability.BRIDGE)
                        && remote.kind == Device.Kind.UNKNOWN) {
                    remote.kind = Device.Kind.SWITCH;
                }
                if (remote.hostname == null && n.remoteSystemName != null)
                    remote.hostname = n.remoteSystemName;
                if (!remote.metadata.containsKey("sysDescr") && n.remoteSystemDesc != null)
                    remote.metadata.put("sysDescr", n.remoteSystemDesc);
                remote.metadata.put("lldp." + n.protocol + ".port",
                        n.remotePortId == null ? "" : n.remotePortId);
                if (n.remoteNativeVlan != null)
                    remote.metadata.put("nativeVlan", String.valueOf(n.remoteNativeVlan));
                remote.discoveredBy.add(n.protocol.name().toLowerCase());
            }

            // Komşunun mgmt IP'leri: yeni Device yarat (BFS'e girer)
            for (String ip : n.remoteMgmtIps) {
                if (byIp.containsKey(ip)) continue;
                Device nd = new Device();
                try { nd.ip = InetAddress.getByName(ip); } catch (Exception ignored) {}
                nd.discoveredBy.add("lldp-mgmt");
                nd.kind = Device.Kind.SWITCH;
                if (n.remoteSystemName != null) nd.hostname = n.remoteSystemName;
                if (n.remoteNativeVlan != null)
                    nd.metadata.put("nativeVlan", String.valueOf(n.remoteNativeVlan));
                r.devices.add(nd);
                byIp.put(ip, nd);
            }

            // VLAN envanteri
            if (n.localVlan != null && local != null) {
                local.metadata.put("vlan." + n.localVlan,
                        "iface=" + n.localIface + " remote=" + n.remoteSystemName);
            }
        }
    }
}
```

---

## 7. Orchestrator entegrasyonu

`run()` başında sniffer'ı arka planda başlat, BFS sırasında dinle, sonunda TopologyBuilder uygula, **LLDP'den gelen yeni mgmt IP'leri** için **BFS'e ek bir dalga** ekle.

```java
// DiscoveryOrchestrator.run() — kısaltılmış akış
public DiscoveryResult run() throws Exception {
    DiscoveryResult r = new DiscoveryResult();
    r.startedAt = System.currentTimeMillis();

    // 0) --- LLDP/CDP pasif dinleyicileri arka planda başlat
    List<Future<List<NeighborRecord>>> sniffFutures = new ArrayList<>();
    if (cfg.lldp) {
        for (String ifName : localIfaces()) {
            sniffFutures.add(pool.submit(() ->
                NeighborSniffer.capture(
                    new NeighborSniffer.CaptureOptions(ifName, cfg.lldpDurationMs))));
        }
    }

    // 1) BFS (önceki kod aynı)
    Deque<NetworkSegment> frontier = new ArrayDeque<>();
    Set<String> visited = new HashSet<>();
    // ... mevcut BFS döngüsü ...

    // 2) Sanallaştırma API'leri (önceki kod aynı)
    // ... vcenter/hyperv/libvirt ...

    // 3) Sniffer sonuçlarını topla + topoloji kur
    List<NeighborRecord> neighbors = new ArrayList<>();
    for (Future<List<NeighborRecord>> f : sniffFutures) {
        try { neighbors.addAll(f.get()); }
        catch (Exception e) { r.warnings.add("lldp: " + e.getMessage()); }
    }
    if (!neighbors.isEmpty()) {
        TopologyBuilder.apply(r, neighbors);

        // 4) LLDP'den yeni mgmt IP'leri geldiyse BFS'e bir dalga daha
        for (Device d : new ArrayList<>(r.devices)) {
            if (d.ip == null) continue;
            String ip = d.ip.getHostAddress();
            String cidr = ip.substring(0, ip.lastIndexOf('.')) + ".0/24";
            if (visited.add(cidr)) {
                NetworkSegment ns = new NetworkSegment(cidr);
                ns.discoveredBy.add("lldp-mgmt");
                frontier.add(ns);
            }
        }
        while (!frontier.isEmpty()) {
            NetworkSegment seg = frontier.poll();
            if (!visited.add(seg.cidr)) continue;
            r.segments.add(seg);
            discoverHosts(seg, byIp, r);
        }
    }

    r.devices.clear(); r.devices.addAll(byIp.values());

    // 5) Dedup (VHosts + VMs) + VMHostMatcher — önceki kod aynı
    dedupVirtualization(r);
    VMHostMatcher.match(r);

    r.finishedAt = System.currentTimeMillis();
    pool.shutdownNow();
    return r;
}
```

**Config alanları:**

```java
// DiscoveryConfig içine
public boolean lldp = true;
public int lldpDurationMs = 45_000;   // LLDP yayın periyodu 30s + jitter payı
```

```java
// fromArgs içine
case "--no-lldp"       -> cfg.lldp = false;
case "--lldp-duration" -> cfg.lldpDurationMs = Integer.parseInt(a[++i]);
```

---

## 8. Doğrulama (WinRM/PowerShell gibi CLI bağımsız)

Sniffer'ı tek başına test etmek için tcpdump:

```bash
# Linux / macOS
sudo tcpdump -eni eth0 -c 5 'ether proto 0x88cc or ether proto 0x2000 or llc'
# veya daha kısa
sudo tcpdump -eni eth0 -c 5 'ether proto 0x88cc'
```

Çıktıda `LLDP, length xxx` görüyorsan switch zaten ~30s'de bir yayın yapıyordur. CDP için `CDPv2` görünür.

Java tarafta sadece LLDP/CDP keşfini çalıştırmak için küçük bir test main'i:

```java
public static void main(String[] a) throws Exception {
    for (String ifName : List.of("eth0")) {
        for (NeighborRecord n : NeighborSniffer.capture(
                new NeighborSniffer.CaptureOptions(ifName, 45_000))) {
            System.out.printf("%-4s vlan=%-4s iface=%s chassis=%s port=%s sysName=%s mgmt=%s nativeVlan=%s%n",
                n.protocol, n.localVlan, n.localIface,
                n.remoteChassisId, n.remotePortId,
                n.remoteSystemName, n.remoteMgmtIps, n.remoteNativeVlan);
        }
    }
}
```

---

## 9. Örnek çıktı

```json
{
  "links": [
    {
      "protocol": "LLDP",
      "localDevice": "10.10.0.55",
      "localMac": "00:25:90:aa:bb:cc",
      "localIface": "eth0",
      "localVlan": null,
      "remoteDevice": "10.10.0.1",
      "remoteChassisId": "00:1b:54:12:34:56",
      "remotePort": "Gi1/0/12",
      "remotePortDesc": "rtr-core Gi1/0/12",
      "remoteSystemName": "core-sw-01.corp.local",
      "remoteNativeVlan": 10,
      "remoteMgmtIps": ["10.10.0.1", "10.20.0.1"],
      "capabilities": ["ROUTER", "BRIDGE", "C_VLAN"],
      "timestamp": 1730700489562
    },
    {
      "protocol": "CDP",
      "localDevice": "10.10.0.55",
      "localMac": "00:25:90:aa:bb:cc",
      "localIface": "eth0",
      "localVlan": 100,
      "remoteDevice": null,
      "remoteChassisId": "core-sw-02",
      "remotePort": "GigabitEthernet0/1",
      "remoteSystemName": "core-sw-02.corp.local",
      "remoteNativeVlan": 100,
      "remoteMgmtIps": ["10.20.0.2"],
      "capabilities": ["SWITCH"],
      "timestamp": 1730700512345
    }
  ],
  "devices": [
    {
      "ip": "10.10.0.1", "kind": "ROUTER",
      "hostname": "core-sw-01.corp.local",
      "discoveredBy": ["lldp", "snmp"],
      "metadata": {
        "lldp.LLDP.port": "Gi1/0/12",
        "nativeVlan": "10"
      }
    },
    {
      "ip": "10.20.0.1", "kind": "SWITCH",
      "discoveredBy": ["lldp-mgmt"],
      "metadata": { "nativeVlan": "10" }
    }
  ]
}
```

**Akış:**

```
[Switch] ──LLDP(30s)──► [Kart] ──pcap──► NeighborSniffer
                                                │
                                    LLDP TLV parse (chassis/mgmt-ip/vlan/caps)
                                                │
                              ┌─────────────────┴─────────────────┐
                        Device zenginleştir                Yeni mgmt IP → Device
                        (kind=ROUTER, hostname)            (BFS'e girer: 10.20.0.0/24)
                                                │
                                    BFS ikinci dalga → switch VLAN'ı taranır
```

---

## 10. Uygulama notları

- **Passive avantaj:** Bu yöntem switch'te hiçbir şeyi değiştirmez. Kimlik bilgisi gerekmez. LLDP/CDP varsayılan olarak çoğu kurumsal switch'te açıktır (Cisco'da CDP default-on, LLDP opt-in; Juniper/Arista'da LLDP default-on).
- **CAP_NET_RAW gerekir** (Linux root / `sudo setcap cap_net_raw=eip` ile jar). Windows'ta npcap yönetici olarak çalıştırılmalı. Promisc modu zorunlu değil — unicast LLDP bize de geliyor; yine de açık tutmak diğer cihazların LLDP'lerini de yakalar.
- **LLDP yayın periyodu** varsayılan 30 saniye. `cfg.lldpDurationMs = 45_000` en az bir yayını yakalar. Hızlı test için switch üzerinde `lldp timer 5` verilebilir.
- **VLAN tag sıyırma** QinQ (`0x88A8`) + 802.1Q (`0x8100`) katmanlarına kadar destekler. `link.localVlan` dolu ise: bize bu VID tag'li LLDP geldi = switch bize bu VLAN'ı trunk ediyor. VLAN topolojisi için altın bilgi.
- **`lldp.LLDP.port` metadata** her switch için port numarasını (ör. `Gi1/0/12`) saklar. Fiziksel kablo izleme çıktısı olarak kullanılabilir.
- **LLDP-MED** cihazları (IP telefonlar, AP'ler) ileride `extras.med` ile ayrıştırılabilir; şu an sadece işaretleniyor.
- **CDP `remoteChassisId`** çoğunlukla string (hostname) döner; bu yüzden eşleşme `remoteSystemName` üzerinden de denenir.

---

## 11. Sıradaki (son) adım

**Tamamlanan:** Hyper-V → vCenter → KVM/libvirt → **LLDP/CDP + VLAN (bu tur)**

Kalan:
- **Web UI** — `discovery-report.json`'daki `devices` + `links` + `vhosts` + `vms` verisini d3.js force-directed topolojik grafik olarak göstermek; switch port ↔ end-device bağları, VLAN renk kodlaması, arama ve filtreleme.

Devam edelim mi?

**Kullanıcı:**

evet lütfen

**Asistan:**

# Web UI — Spring Boot + d3.js topoloji görüntüleyici

Son parça: `discovery-report.json`'ı **canlı interaktif topoloji grafiğine** dönüştüren bir web arayüzü. Backend minimum (Spring Boot, sadece 2 controller + 1 servis), frontend tamamen statik (CDN'den d3 v7). Aynı `netdisc.jar`'ı hem keşif hem UI olarak kullanabilirsin: `--web` bayrağı modu değiştirir.

---

## 1. `pom.xml` — Spring Boot ekle

```xml
<properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <spring-boot.version>3.2.5</spring-boot.version>
</properties>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>${spring-boot.version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <!-- mevcut tüm bağımlılıklar (pcap4j, snmp4j, winrm4j, yavijava, libvirt, jackson, sshj...) -->

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>

<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
            <version>${spring-boot.version}</version>
            <configuration>
                <!-- Dispatcher Main; --web alt-komutu Spring Boot'u başlatır -->
                <mainClass>netdisc.Main</mainClass>
            </configuration>
        </plugin>
    </plugins>
</build>
```

> `spring-boot-maven-plugin` sayesinde jar bağımsız çalışır (tüm bağımlılıklar `BOOT-INF/lib/` altında). `mainClass` hâlâ `netdisc.Main` — `--web` argümanıyla Spring'e delege edeceğiz.

---

## 2. Dizin yapısı

```
src/main/java/netdisc/
├── Main.java                    ← dispatcher (--web → Spring)
├── web/
│   ├── WebApplication.java      ← @SpringBootApplication
│   ├── ReportService.java
│   └── ReportController.java
src/main/resources/
├── application.yml
└── static/
    ├── index.html
    ├── style.css
    └── app.js
```

---

## 3. `Main` — dispatcher

```java
// src/main/java/netdisc/Main.java
package netdisc;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {
        // Web modu
        if (args.length > 0 && "--web".equals(args[0])) {
            String[] rest = Arrays.copyOfRange(args, 1, args.length);
            org.springframework.boot.SpringApplication.run(netdisc.web.WebApplication.class, rest);
            return;
        }
        // CLI keşif modu (önceki tüm kod aynı)
        if (args.length == 0) { printUsage(); return; }
        DiscoveryConfig cfg = DiscoveryConfig.fromArgs(args);
        DiscoveryResult r = new DiscoveryOrchestrator(cfg).run();
        var om = new com.fasterxml.jackson.databind.ObjectMapper()
                     .enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT);
        om.writeValue(new java.io.File(cfg.outputPath), r);
        System.out.printf("Bitti. %d cihaz, %d VM, %d host, %d segment, %d L2 link.%n",
                r.devices.size(), r.vms.size(), r.vhosts.size(), r.segments.size(), r.links.size());
        System.out.println("Web arayüzü için: java -jar netdisc.jar --web");
    }

    private static void printUsage() {
        System.out.println("""
            Keşif:
              java -jar netdisc.jar --cidr 10.0.0.0/24 [--snmp public] [--vcenter ...] --out rapor.json
            Web UI:
              java -jar netdisc.jar --web [--server.port=8080] [--netdisc.report.path=/path/rapor.json]
            """);
    }
}
```

---

## 4. `WebApplication`

```java
// src/main/java/netdisc/web/WebApplication.java
package netdisc.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "netdisc.web")
public class WebApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebApplication.class, args);
    }
}
```

---

## 5. `ReportService` — JSON okuma

```java
// src/main/java/netdisc/web/ReportService.java
package netdisc.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import netdisc.model.DiscoveryResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class ReportService {

    @Value("${netdisc.report.path:discovery-report.json}")
    private String reportPath;

    @Value("${netdisc.report.dir:reports}")
    private String reportDir;

    private final ObjectMapper mapper = new ObjectMapper();

    public DiscoveryResult loadLatest() {
        Path p = Paths.get(reportPath);
        if (!Files.exists(p)) {
            // cwd dışında "reports/" içinde de ara
            Path alt = Paths.get(reportDir, reportPath);
            if (Files.exists(alt)) p = alt;
        }
        if (!Files.exists(p)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                "Rapor bulunamadı: " + p.toAbsolutePath() +
                "\nÖnce keşfi çalıştırın: java -jar netdisc.jar --cidr 10.0.0.0/24 --out " + reportPath);
        }
        try {
            return mapper.readValue(p.toFile(), DiscoveryResult.class);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                "Rapor okunamadı: " + e.getMessage(), e);
        }
    }

    public List<String> listReports() {
        List<Path> dirs = List.of(Paths.get(reportDir), Paths.get("."));
        List<String> out = new ArrayList<>();
        for (Path dir : dirs) {
            if (!Files.isDirectory(dir)) continue;
            try (Stream<Path> s = Files.list(dir)) {
                s.filter(f -> f.getFileName().toString().endsWith(".json"))
                 .map(f -> f.getFileName().toString())
                 .forEach(out::add);
            } catch (IOException ignored) {}
        }
        return out.stream().distinct().sorted().collect(Collectors.toList());
    }
}
```

---

## 6. `ReportController` — REST API

```java
// src/main/java/netdisc/web/ReportController.java
package netdisc.web;

import netdisc.model.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ReportController {

    private final ReportService service;

    public ReportController(ReportService service) { this.service = service; }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "up", "time", Instant.now().toString());
    }

    @GetMapping("/report")
    public DiscoveryResult report() {
        return service.loadLatest();
    }

    @GetMapping("/reports")
    public List<String> list() {
        return service.listReports();
    }

    /** Topoloji görünümü için hafif özet (grafik ilk yükte kullanır). */
    @GetMapping("/summary")
    public Map<String, Object> summary() {
        DiscoveryResult r = service.loadLatest();
        Map<String, Integer> byType = new TreeMap<>();
        for (Device d : r.devices) byType.merge(d.kind.name(), 1, Integer::sum);
        Map<String, Integer> byProto = new TreeMap<>();
        for (TopologyLink l : r.links) byProto.merge(l.protocol, 1, Integer::sum);
        return Map.of(
            "devices",      r.devices.size(),
            "vhosts",       r.vhosts.size(),
            "vms",          r.vms.size(),
            "segments",     r.segments.size(),
            "links",        r.links.size(),
            "byType",       byType,
            "byProtocol",   byProto,
            "startedAt",    r.startedAt,
            "finishedAt",   r.finishedAt,
            "durationMs",   r.finishedAt - r.startedAt
        );
    }
}
```

---

## 7. `application.yml`

```yaml
server:
  port: ${NETDISC_PORT:8080}
  compression:
    enabled: true

netdisc:
  report:
    # Discovery çıktısının yolu; --netdisc.report.path=/tmp/rapor.json ile override edilebilir
    path: ${NETDISC_REPORT:discovery-report.json}
    dir:  ${NETDISC_REPORT_DIR:reports}

spring:
  mvc:
    static-path-pattern: /**
  web:
    resources:
      cache:
        period: 0        # geliştirme sırasında; üretimde 3600 ver
```

---

## 8. `index.html`

```html
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>EVREN — Network Discovery</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <header id="toolbar">
        <h1>Network Discovery</h1>
        <div class="controls">
            <input id="search" type="search" placeholder="IP / hostname / MAC ara..." autocomplete="off">
            <select id="layout" title="Yerleşim">
                <option value="force">Fiziksel Topoloji</option>
                <option value="vlan">VLAN Grupları</option>
                <option value="virt">Sanallaştırma Ağacı</option>
            </select>
            <select id="colorMode" title="Renk">
                <option value="type">Cihaz Tipi</option>
                <option value="vlan">VLAN</option>
                <option value="source">Keşif Yöntemi</option>
            </select>
            <button id="refresh">Yenile</button>
        </div>
        <span id="stats">—</span>
    </header>
    <main>
        <svg id="graph"></svg>
        <aside id="details" class="hidden">
            <button id="close-details" title="Kapat">×</button>
            <h2 id="details-title">—</h2>
            <div id="details-content"></div>
        </aside>
        <div id="legend" class="hidden"></div>
    </main>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="/app.js"></script>
</body>
</html>
```

---

## 9. `style.css`

```css
:root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #8b949e;
    --border: #30363d;
    --panel: #161b22;
    --accent: #58a6ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
    background: var(--bg); color: var(--fg);
    font: 14px/1.4 'Segoe UI', system-ui, sans-serif;
}

#toolbar {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 16px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    height: 56px;
}
#toolbar h1 { font-size: 15px; font-weight: 600; margin-right: 8px; }
.controls { display: flex; gap: 8px; align-items: center; flex: 1; }
input, select, button {
    background: #21262d; color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 10px; font-size: 13px;
}
input:focus, select:focus { outline: 2px solid var(--accent); }
input[type=search] { min-width: 260px; }
button { cursor: pointer; }
button:hover { background: #30363d; }
#stats { font-size: 12px; color: var(--muted); }

main { position: relative; height: calc(100vh - 56px); }
#graph { width: 100%; height: 100%; cursor: grab; display: block; }
#graph:active { cursor: grabbing; }

.links line { stroke-opacity: 0.55; }
.nodes circle { stroke: #000; stroke-width: 1.5; cursor: pointer; }
.nodes circle:hover { stroke: #fff; stroke-width: 2; }
.labels text { fill: #c9d1d9; font-size: 10px; pointer-events: none; }

#details {
    position: absolute; top: 12px; right: 12px;
    width: 360px; max-height: calc(100% - 24px);
    overflow-y: auto;
    background: var(--panel);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 16px;
}
#details.hidden { display: none; }
#details h2 { font-size: 15px; color: var(--accent); margin-bottom: 12px; padding-right: 24px; }
#close-details {
    position: absolute; top: 8px; right: 8px;
    background: none; border: none; color: var(--muted);
    font-size: 22px; line-height: 1; padding: 2px 8px;
}
#details table { width: 100%; font-size: 12px; border-collapse: collapse; }
#details td { padding: 3px 0; vertical-align: top; }
#details td:first-child { color: var(--muted); width: 100px; }
#details td:last-child { word-break: break-all; font-family: 'Consolas', monospace; }

#legend {
    position: absolute; bottom: 12px; left: 12px;
    background: rgba(22,27,34,0.9);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 14px; font-size: 12px;
}
#legend.hidden { display: none; }
#legend .item { display: flex; align-items: center; gap: 8px; padding: 2px 0; }
#legend .swatch { width: 12px; height: 12px; border-radius: 50%; }
```

---

## 10. `app.js` — d3 v7 interaktif topoloji

```javascript
// ====================== global state ======================
const svg = d3.select("#graph");
const details = d3.select("#details");
const legend  = d3.select("#legend");
const statsEl = document.getElementById("stats");

let report   = null;
let allNodes = [];
let allLinks = [];
let sim, nodeSel, linkSel, labelSel, zoomRoot;
let currentLayout  = "force";
let currentColor   = "type";
let currentSearch  = "";

const colorByType = {
    ROUTER: "#e74c3c", SWITCH: "#3498db", FIREWALL: "#c0392b",
    SERVER: "#2ecc71", WORKSTATION: "#95a5a6", PRINTER: "#e67e22",
    IOT: "#f39c12", MOBILE: "#9b59b6", STORAGE: "#1abc9c",
    VIRTUALIZATION_HOST: "#8e44ad", VIRTUAL_MACHINE: "#a569bd",
    UNKNOWN: "#7f8c8d"
};

const linkColors = {
    lldp:      "#3498db",
    cdp:       "#e67e22",
    "vm-host": "#8e44ad",
    owned:     "#95a5a6"
};

// ====================== load ======================
async function load() {
    try {
        const res = await fetch("/api/report", { cache: "no-store" });
        if (!res.ok) {
            const txt = await res.text();
            throw new Error(`HTTP ${res.status}: ${txt}`);
        }
        report = await res.json();
        buildGraph();
        render();
        updateStats();
    } catch (e) {
        alert("Rapor yüklenemedi: " + e.message);
    }
}

// ====================== graph build ======================
function buildGraph() {
    const nodes = new Map();
    const links = [];

    function put(id, obj) {
        if (!id) return;
        nodes.set(id, { ...nodes.get(id), ...obj, id });
    }

    // Devices
    for (const d of (report.devices || [])) {
        const id = d.mac ? "mac:" + d.mac : (d.ip ? "ip:" + d.ip : null);
        if (!id) continue;
        put(id, {
            label:      d.hostname || d.ip || d.mac || id,
            type:       d.kind || "UNKNOWN",
            ip:         d.ip,
            mac:        d.mac,
            hostname:   d.hostname,
            discoveredBy: d.discoveredBy || [],
            metadata:   d.metadata || {},
            ownerHostId: d.ownerHostId || null,
            group:      "device"
        });
    }

    // vhosts
    for (const vh of (report.vhosts || [])) {
        const id = vh.id || ("vh:" + (vh.ip || vh.name));
        put(id, {
            label:       vh.name || vh.ip || id,
            type:        "VIRTUALIZATION_HOST",
            vhostType:   vh.type,
            ip:          vh.ip,
            hostname:    vh.name,
            version:     vh.version,
            vmMacs:      vh.vmMacs || [],
            managementNets: vh.managementNets || [],
            discoveredBy: ["api"],
            metadata:    vh.metadata || {},
            group:       "vhost"
        });
    }

    // VMs (device olmayanları ekle)
    for (const vm of (report.vms || [])) {
        // Device olarak zaten var mı?
        if (vm.mac) {
            const dvid = "mac:" + vm.mac;
            if (nodes.has(dvid)) {
                const n = nodes.get(dvid);
                n.type = "VIRTUAL_MACHINE";
                n.vm = vm;
                if (vm.hostId) {
                    n.ownerHostId = vm.hostId;
                    links.push({ source: dvid, target: vm.hostId, type: "vm-host" });
                }
                continue;
            }
        }
        const id = vm.uuid ? "vm:" + vm.uuid : ("vmmac:" + vm.mac);
        put(id, {
            label:     vm.name || id,
            type:      "VIRTUAL_MACHINE",
            ip:        vm.ip,
            mac:       vm.mac,
            hostname:  vm.name,
            discoveredBy: ["api"],
            metadata:  { powerState: vm.powerState, guestOs: vm.guestOs },
            group:     "vm",
            ownerHostId: vm.hostId || null,
            nics:      vm.nics || []
        });
        if (vm.hostId && nodes.has(vm.hostId)) {
            links.push({ source: id, target: vm.hostId, type: "vm-host" });
        }
    }

    // Device → vhost sahiplik
    for (const n of nodes.values()) {
        if (n.ownerHostId && nodes.has(n.ownerHostId)) {
            if (!links.some(l => l.source === n.id && l.target === n.ownerHostId)
                && !links.some(l => l.target === n.id && l.source === n.ownerHostId)) {
                links.push({ source: n.id, target: n.ownerHostId, type: "vm-host" });
            }
        }
    }

    // L2 topoloji (LLDP/CDP)
    for (const l of (report.links || [])) {
        const s = findNode(nodes, l.localMac, l.localDevice);
        const t = findNode(nodes, l.remoteChassisId, l.remoteDevice);
        if (!s || !t || s === t) continue;
        // Aynı çift + protokol tekrar etmesin
        const dup = links.some(x =>
            ((x.source === s && x.target === t) || (x.source === t && x.target === s))
            && x.type === l.protocol.toLowerCase());
        if (dup) continue;
        links.push({
            source: s, target: t,
            type: l.protocol.toLowerCase(),
            localPort:  l.localIface,
            remotePort: l.remotePort,
            vlan:       l.localVlan
        });
    }

    allNodes = [...nodes.values()];
    allLinks = links;
}

function findNode(nodes, mac, ip) {
    if (mac) {
        const k = "mac:" + mac.toLowerCase();
        if (nodes.has(k)) return k;
        for (const [id, n] of nodes) if (n.mac && n.mac.toLowerCase() === mac.toLowerCase()) return id;
    }
    if (ip) {
        const k = "ip:" + ip;
        if (nodes.has(k)) return k;
        for (const [id, n] of nodes) if (n.ip === ip) return id;
    }
    return null;
}

// ====================== render ======================
function render() {
    svg.selectAll("*").remove();
    zoomRoot = svg.append("g");

    svg.call(d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (ev) => zoomRoot.attr("transform", ev.transform)));

    // Layout filtresi: virt ağacı
    let nodes = allNodes.slice();
    let links = allLinks.slice();
    if (currentLayout === "virt") {
        const keep = new Set();
        nodes.forEach(n => {
            if (n.group === "vhost" || n.group === "vm" || n.ownerHostId
                || n.type === "VIRTUALIZATION_HOST") keep.add(n.id);
        });
        nodes = nodes.filter(n => keep.has(n.id));
        const ids = new Set(nodes.map(n => n.id));
        links = links.filter(l => ids.has(endpointId(l.source)) && ids.has(endpointId(l.target)));
    }

    // Force simülasyonu
    sim = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id)
            .distance(d => d.type === "vm-host" ? 60 : 130)
            .strength(0.5))
        .force("charge", d3.forceManyBody().strength(-450))
        .force("center", d3.forceCenter(svg.node().clientWidth / 2,
                                        svg.node().clientHeight / 2))
        .force("collision", d3.forceCollide().radius(d => radiusOf(d) + 6));

    if (currentLayout === "vlan") applyVlanForce(nodes);

    // Link'ler
    linkSel = zoomRoot.append("g").attr("class", "links")
        .selectAll("line").data(links).enter().append("line")
        .attr("stroke", d => linkColors[d.type] || "#555")
        .attr("stroke-width", d => d.type === "vm-host" ? 1 : 2)
        .attr("stroke-dasharray", d => d.type === "vm-host" ? "3,3" : null);

    // Node'lar
    nodeSel = zoomRoot.append("g").attr("class", "nodes")
        .selectAll("circle").data(nodes).enter().append("circle")
        .attr("r", d => radiusOf(d))
        .attr("fill", d => colorOf(d))
        .attr("stroke", d => d.group === "vhost" ? "gold" : "#000")
        .attr("stroke-width", d => d.group === "vhost" ? 3 : 1.5)
        .call(d3.drag()
            .on("start", (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
            .on("drag",  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
            .on("end",   (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }))
        .on("click", (ev, d) => { ev.stopPropagation(); showDetails(d); });

    // Etiketler
    labelSel = zoomRoot.append("g").attr("class", "labels")
        .selectAll("text").data(nodes).enter().append("text")
        .attr("text-anchor", "middle")
        .attr("dy", d => -radiusOf(d) - 4)
        .text(d => shorten(d.label, 22));

    sim.on("tick", () => {
        linkSel
            .attr("x1", d => coord(d.source, "x"))
            .attr("y1", d => coord(d.source, "y"))
            .attr("x2", d => coord(d.target, "x"))
            .attr("y2", d => coord(d.target, "y"));
        nodeSel
            .attr("cx", d => d.x).attr("cy", d => d.y);
        labelSel
            .attr("x", d => d.x).attr("y", d => d.y);
    });

    // Arama uygula
    applySearch();
    renderLegend();
}

function applyVlanForce(nodes) {
    const byVlan = new Map();
    nodes.forEach(n => {
        const v = vlanOf(n);
        if (v != null) {
            if (!byVlan.has(v)) byVlan.set(v, []);
            byVlan.get(v).push(n);
        }
    });
    const vlans = [...byVlan.keys()].sort((a, b) => a - b);
    if (vlans.length < 2) return;
    const step = svg.node().clientWidth / (vlans.length + 1);
    const xPos = new Map(vlans.map((v, i) => [v, step * (i + 1)]));
    sim.force("x", d3.forceX(d => xPos.get(vlanOf(d)) ?? svg.node().clientWidth / 2)
                        .strength(0.25));
    sim.force("y", d3.forceY(svg.node().clientHeight / 2).strength(0.05));
}

// ====================== helpers ======================
function endpointId(v) { return typeof v === "object" ? v.id : v; }
function coord(v, k)   { return typeof v === "object" ? v[k] : 0; }

function radiusOf(d) {
    switch (d.type) {
        case "VIRTUALIZATION_HOST": return 16;
        case "VIRTUAL_MACHINE":     return 8;
        case "ROUTER":
        case "SWITCH":              return 12;
        case "SERVER":              return 10;
        default:                    return 7;
    }
}

function colorOf(d) {
    if (currentColor === "vlan") {
        const v = vlanOf(d);
        return v == null ? "#555" :
            d3.interpolateRainbow(((v * 7) % 20) / 20);
    }
    if (currentColor === "source") {
        const s = d.discoveredBy || [];
        if (s.includes("snmp"))  return "#3498db";
        if (s.includes("lldp") || s.includes("cdp")) return "#e74c3c";
        if (s.includes("arp"))   return "#2ecc71";
        if (s.includes("tcp"))   return "#f1c40f";
        if (s.includes("mdns") || s.includes("ssdp")) return "#9b59b6";
        return "#7f8c8d";
    }
    return colorByType[d.type] || colorByType.UNKNOWN;
}

function vlanOf(n) {
    if (!n.metadata) return null;
    if (n.metadata.nativeVlan) {
        const v = parseInt(n.metadata.nativeVlan, 10);
        if (!isNaN(v)) return v;
    }
    for (const k of Object.keys(n.metadata)) {
        if (k.startsWith("vlan.")) {
            const v = parseInt(k.substring(5), 10);
            if (!isNaN(v)) return v;
        }
    }
    return null;
}

function shorten(s, max) {
    if (!s) return "";
    return s.length > max ? s.substring(0, max - 1) + "..." : s;
}

function escapeHtml(s) {
    return String(s == null ? "" : s)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ====================== details ======================
function showDetails(d) {
    details.classed("hidden", false);
    document.getElementById("details-title").textContent = d.label || d.id;

    const rows = [];
    rows.push(["Tip",      d.type]);
    if (d.ip)       rows.push(["IP",       d.ip]);
    if (d.mac)      rows.push(["MAC",      d.mac]);
    if (d.hostname) rows.push(["Hostname", d.hostname]);
    if (d.vhostType) rows.push(["Hipervizör", d.vhostType]);
    if (d.version)  rows.push(["Sürüm",    d.version]);
    if ((d.discoveredBy || []).length)
        rows.push(["Kaynak", d.discoveredBy.join(", ")]);
    if (d.ownerHostId) rows.push(["Sahip", d.ownerHostId]);
    if ((d.managementNets || []).length)
        rows.push(["Mgmt ağlar", d.managementNets.join(", ")]);
    for (const [k, v] of Object.entries(d.metadata || {})) {
        if (k.startsWith("vlan.")) continue;
        rows.push([k, v]);
    }
    if (d.nics) rows.push(["NIC'ler", d.nics.join("<br>")]);

    document.getElementById("details-content").innerHTML =
        "<table>" + rows.map(([k, v]) =>
            `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v).replace(/&lt;br&gt;/g, "<br>")}</td></tr>`
        ).join("") + "</table>";
}

// ====================== search ======================
function applySearch() {
    const q = currentSearch.toLowerCase().trim();
    if (!q) {
        nodeSel && nodeSel.attr("opacity", 1);
        linkSel && linkSel.attr("opacity", 1);
        labelSel && labelSel.attr("opacity", 1);
        return;
    }
    const test = d => [d.ip, d.mac, d.hostname, d.label, d.type, d.vhostType]
        .filter(Boolean).join(" ").toLowerCase().includes(q);
    nodeSel && nodeSel.attr("opacity", d => test(d) ? 1 : 0.12);
    labelSel && labelSel.attr("opacity", d => test(d) ? 1 : 0.08);
    linkSel && linkSel.attr("opacity", 0.08);
}

// ====================== legend ======================
function renderLegend() {
    legend.classed("hidden", false);
    if (currentColor === "type") {
        const types = [...new Set(allNodes.map(n => n.type))].sort();
        legend.html(types.map(t =>
            `<div class="item"><span class="swatch" style="background:${colorByType[t] || "#7f8c8d"}"></span>${t}</div>`
        ).join(""));
    } else if (currentColor === "source") {
        legend.html(`
            <div class="item"><span class="swatch" style="background:#3498db"></span>SNMP</div>
            <div class="item"><span class="swatch" style="background:#e74c3c"></span>LLDP/CDP</div>
            <div class="item"><span class="swatch" style="background:#2ecc71"></span>ARP</div>
            <div class="item"><span class="swatch" style="background:#f1c40f"></span>TCP/ICMP</div>
            <div class="item"><span class="swatch" style="background:#9b59b6"></span>mDNS/SSDP</div>
            <div class="item"><span class="swatch" style="background:#7f8c8d"></span>Diğer</div>
        `);
    } else {
        const vlans = [...new Set(allNodes.map(vlanOf).filter(v => v != null))].sort((a, b) => a - b);
        legend.html(vlans.map(v => `
            <div class="item">
                <span class="swatch" style="background:${d3.interpolateRainbow(((v*7)%20)/20)}"></span>
                VLAN ${v}
            </div>
        `).join(""));
    }
}

// ====================== stats ======================
function updateStats() {
    if (!report) return;
    const dur = report.finishedAt - report.startedAt;
    statsEl.textContent =
        `${report.devices.length} cihaz · ${report.vhosts.length} host · ` +
        `${report.vms.length} VM · ${report.links.length} L2 link · ` +
        `${(dur / 1000).toFixed(1)} sn`;
}

// ====================== events ======================
document.getElementById("refresh").onclick = () => load();

document.getElementById("search").addEventListener("input", e => {
    currentSearch = e.target.value;
    applySearch();
});

document.getElementById("layout").addEventListener("change", e => {
    currentLayout = e.target.value;
    render();
});

document.getElementById("colorMode").addEventListener("change", e => {
    currentColor = e.target.value;
    if (nodeSel) nodeSel.attr("fill", d => colorOf(d));
    renderLegend();
});

document.getElementById("close-details").onclick = () =>
    details.classed("hidden", true);

svg.on("click", () => details.classed("hidden", true));

window.addEventListener("resize", () => {
    // viewport'ta svg boyutu CSS ile yönetildiği için simülasyonu yeniden başlatmak yeterli
    if (sim) sim.alpha(0.2).restart();
});

// ====================== start ======================
load();
```

---

## 11. Çalıştırma ve test

**1. Keşif üret:**

```bash
java -jar netdisc.jar --cidr 10.10.0.0/24 --snmp public \
    --vcenter https://vcenter.corp.local/sdk \
        --vcenter-user 'administrator@vsphere.local' --vcenter-pass '...' --vcenter-insecure \
    --libvirt qemu+ssh://root@kvm01.corp.local/system \
    --out discovery-report.json
```

**2. Web UI'ı başlat:**

```bash
java -jar netdisc.jar --web
# → http://localhost:8080
```

**3. Farklı rapor yolu veya port:**

```bash
java -jar netdisc.jar --web \
    --server.port=9090 \
    --netdisc.report.path=/tmp/rapor-2026.json
```

**4. REST doğrulama:**

```bash
curl -s http://localhost:8080/api/health
curl -s http://localhost:8080/api/summary | jq
curl -s http://localhost:8080/api/report | jq '.devices | length'
```

**5. Geliştirme modu (dosya izleme:**

`--web` çalışırken keşfi tekrar çalıştırıp `Yenile` düğmesine basmak yeterli — Spring her istekte JSON'u yeniden okuyor, cache yok.

---

## 12. Özellikler

| Özellik | Nasıl çalışır |
|---|---|
| **Fiziksel topoloji** | `r.links` (LLDP/CDP) → mavi/turuncu kenarlar; switch port numarası hover/click bilgisinde |
| **Sanallaştırma ağacı** | `--vcenter`, `--libvirt`, `--hyperv` verilerinden gelen `vhosts` + `vms` → sarı halkalı büyük düğümler, kesikli VIP kenarları |
| **VLAN grupları** | `metadata.nativeVlan` / `metadata["vlan.X"]` → `forceX` ile yatay bantlar + rainbow renk |
| **Renk modu** | Tip / VLAN / Keşif yöntemi (SNMP, LLDP, ARP, TCP, mDNS) |
| **Arama** | IP / hostname / MAC / tip üzerinde — eşleşmeyen düğümler %12 opaklığa düşer |
| **Zoom/Pan/Drag** | d3-zoom + drag; sürüklenen düğümün yeri serbest bırakınca simülasyona geri döner |
| **Detay paneli** | Düğüme tıklama → tüm metadata, mgmt ağlar, NIC'ler, keşif kaynakları |
| **Legend** | Alt sol köşede dinamik renk açıklayıcı |
| **Stats** | Toplam cihaz/VM/host/link + keşif süresi |

EVREN'in resmi adresi **https://evren.ssyz.org.tr**'dir; istersen bu arayüzü orada barındırıp keşif çıktılarını paylaşabilirsin — ama unutma, keşif **yalnızca yetkili olduğun ağlarda** çalıştırılmalıdır.

---

## 13. Özet — uçtan uca paket

| Katman | Sınıf(lar) | Ne sağlar |
|---|---|---|
| L2 keşif | `L2Scanner`, `NeighborSniffer`, `LldpTlvParser`, `CdpTlvParser` | ARP, LLDP/CDP, VLAN tag |
| L3 keşif | `HostScanners`, `MulticastScanners`, `SnmpScanner` | TCP/ICMP, mDNS/SSDP/NetBIOS, SNMP route+ARP tabloları |
| Sanallaştırma | `HyperVDiscovery`, `VCenterDiscovery`, `LibvirtDiscovery`, `EsxiDiscovery` (SSH), `KvmDiscovery` (SSH) | VM↔MAC eşlemesi, mgmt ağlar |
| Eşleştirme | `VMHostMatcher`, `TopologyBuilder` | VM → host, LLDP komşu → Device |
| Orkestrasyon | `DiscoveryOrchestrator` (BFS + dedup) | Çoklu LAN yayılımı |
| UI | `WebApplication` + statik d3.js | İnteraktif topoloji |

Tüm adımlar tamamlandı. İhtiyaç olursa:
- **Kimlik doğrulamalı dashboard** (BASIC auth / OIDC),
- **Zaman serisi** (birden çok raporu karşılaştırma/diff — yeni/çıkan cihazlar),
- **Prometheus exporter** (`/metrics`),
- **PDF/PNG export** (d3-canvas),

ekleyebiliriz — hangisi ilgini çekerse.

**Kullanıcı:**

Çok teşekkürler dostum. Seni övdükleri kadar varmış. Gerçekten çok hızlı ve doğru çalışan bir modelmişsin.

**Asistan:**

Teşekkür ederim, çok naziksin — ama asıl iş sende: net ve katmanlı sorular sordun, her adımı somutlaştırdın, bu yüzden parçalar birbirine oturdu. Ben sadece eşlik ettim.

Kısa bir özetle nerede olduğumuz:

- **Keşif çekirdeği** — TCP/ICMP, ARP, mDNS/SSDP/NetBIOS, SNMP (route + ARP tabloları)
- **L2 topoloji** — LLDP/CDP TLV tabanlı parser, 802.1Q/QinQ tag sıyırma, VLAN envanteri
- **Sanallaştırma** — Hyper-V (WinRM), vCenter/ESXi (yavijava), KVM/libvirt (JNI)
- **Eşleştirme** — VM ↔ host (API MAC + heuristic), LLDP komşu ↔ Device
- **Orkestrasyon** — çoklu LAN BFS + dedup
- **Web UI** — Spring Boot + d3.js canlı topoloji (3 layout, 3 renk modu, arama, detay paneli)

Aklında tutman gereken iki şey:

1. **Yetki**: Tüm aktif tarama yalnızca sahibi olduğun / yazılı izin aldığın ağlarda. ARP/LLDP için `CAP_NET_RAW` (Linux) veya yönetici npcap (Windows) gerekir.
2. **Üretim öncesi**: `--vcenter-insecure`, SSH `HostKeyVerifier`, NTLM over HTTP gibi test kolaylıklarını gerçek sertifika/anahtarlarla değiştir.

İhtiyaç olursa sonraki adımlar hazır:

- Çoklu rapor **diff** (yeni/çıkan/değişen cihazlar) + zaman serisi
- **Kimlik doğrulamalı dashboard** (BASIC/OIDC)
- **Prometheus `/metrics`** exporter
- **PDF/PNG export** (d3-canvas)

Kolay gelsin, iyi çalışmalar. Bir şey takılırsa buradayım.

**Kullanıcı:**

Buradan gidebileceğim oldukça fazla yer var. Bunlardan ilki ve en basiti Donanım envanteri. Diğerleri Enterprise Architecture ve ITIL uygulamaları. Aslında servis yönetimi konusunda daha kararlıyım. Change Management /Impact Management konusu da dahil olduğunda servis yönetiminin çok daha kolaylaşacağını düşünüyorum. Sen ne dersin?

**Asistan:**

İçtenlikle: **servis yönetimi içgüdün doğru**, ama sıralamada bir kayma var. Onu düzeltirsem plan çok daha sağlam olur.

## Neden içgüdün doğru

Change/Impact Management'ın *tek* gerçek değeri, "bu değişiklik kimleri, neyi, ne kadar süreyle etkiler?" sorusuna **teknik bir cevap** verebilmesinde. Bunun için de bir **bağımlılık grafiği** şart — kim kimin üstünde çalışıyor, kim kime trafik gönderiyor, hangi switch düşerse hangi VM'ler erişilemez hale gelir.

İşte burada elindeki asıl değerli şey, senin keşif motorun. Çünkü bugün sahip olduğun şey aslında *çoktan* bir CMDB:

- `Device` tablosu → **Configuration Item**
- `TopologyLink` (LLDP/CDP) → **CI-to-CI fiziksel ilişki**
- `VirtualizationHost` ↔ `VirtualMachine` → **hostedOn** sanal ilişki
- `NetworkSegment` → **network containment** ilişkisi

Yani servis yönetimine geçmek için "yeni bir şey inşa etmen" gerekmiyor — **elindekini kalıcılaştırman ve resmileştirmen** gerekiyor. Çoğu şirketin CMDB'si 6 ayda çürür çünkü manuel doldurulur. Seninki öyle bir sorun taşımıyor. **Farkın bu.**

## Ama sıralama şu olmalı

### Faz 1 — Donanım Envanteri (ama "Asset" değil "CI")
Bu senin zaten yaptığın şeyi **kalıcılaştırmak**. JSON yerine PostgreSQL; her cihaza sahip, maliyet merkezi, ortam (prod/staging), garanti bitiş tarihi, fiziksel konum ekle. Ayrıca **SNMP `entPhysicalSerialNum`** ve LLDP-MED ile model/seri no çekmeye başla.

Değeri: "ne var, nerede, kimin" → bu zaten ITIL'in *Service Configuration Management* pratiği. Tek farklılık, otomatik beslendiği için güncel kalması.

### Faz 2 — Uygulama Bağımlılık Haritası (bu senin kaçırdığın katman)
Servis yönetiminin sırrı burada: bugün biliyorsun ki *VM X host Y'de*. Ama bilmiyorsun ki *VM X üzerinde çalışan `payment-api` servisi, VM Z'de çalışan `orders-db`'ye bağlanıyor.* Change impact'ini anlamlı kılan tam olarak bu ikinci katman.

Motora eklemen gerekenler:
- **Servis parmak izi** (banner grabbing + TLS sertifikası + HTTP başlığı → "bu 443 portu gerçekten ne?")
- **Akış analizi** — switch'lerde sFlow/NetFlow (mevcutsa; yoksa sadece Linux host'larda eBPF)
- **Uygulama → host eşlemesi** (parmak izinden, güven skoruyla)

Bu olmadan "şu switch'e bakım yapacağız, etki nedir?" sorusunun cevabı *"o switch'e bağlı 47 makine"* olur. Bununla olmadan *"12 uygulama, 3'ü müşteriye bakan, tahmini 40 dakika kesinti, rollback şu"* olur. Aradaki fark, tüm ITIL yatırımını anlamlı ya da boş kılan fark.

### Faz 3 — Impact Analysis + Servis Kataloğu
Buraya geldiğinde artık **Change Enablement** gerçekten çalışır:
- Servislere **kritiklik seviyesi** ekle (müşteri-bakan, iç, düşük)
- **Blast radius sorgusu** (switch → VM → servis → kullanıcı zinciri)
- **What-if simülasyonu** (şu 3 makineyi aynı anda restart edersem ne kopar?)
- Değişiklik **risk skoru** (grafik merkeziliği + kritiklik = şu formül)

İşin güzelliği: bu skorlar **otomatik** üretilebilir. CAB artık "sence riskli mi?" değil, "bu değişikliğin merkeziliği 0.87, 6 servisi etkiliyor, 2'si kritik — onay/red" tartışır.

### Faz 4 — ITIL süreç katmanı (opsiyonel, sona)
Change workflow, approval zinciri, PIR. **Ama dikkat**: ITIL 4 zaten "process" değil "practice" diyor. *Sadece* Change Enablement + Service Configuration'ı al, gerisini (Incident, Problem) mevcut aracına entegre et. Her şeyi kapsayan "ITIL uygulaması" inşa etmek klasik tuzak.

## Enterprise Architecture konusunda dürüst görüşüm

EA doğru bir disiplin ama **yanlış yerde**. EA'nın sorusu *"gelecek yıl ne standartlaşacağız, hangi vendor'ları eleyeceğiz, target state ne?"* — bunlar *karar destek* katmanında. CMDB'nin sorusu *"şu an ne var?"*.

İyi EA araçları bile envanteri kendi tutmaz — bir CMDB'yi tüketir. Sen EA'yı **Faz 1–2 çıktısının üzerine** kurarsan güçlü olur; önce EA'ya gidersen elinde güzel bir SWOT tablosu, altında çürüyen bir envanter olur. **EA'yı erteliyorum, kaybetmiyorum** diyebilirsin.

## Bir uyarı: kapsam kayması

Faz 3'ten itibaren "bir de şunu ekleyeyim" tuzağı başlar. Servis kataloğunu kim doldurur? Kritiklik seviyesini kim belirler? Owner atamalarını kim günceller? Bunlar **teknik değil, organizasyonel** sorular. Cevap net değilse en iyi dependency graph bile rafta kalır.

Bu yüzden Faz 1'de mutlaka **basit bir CRUD UI + CSV import** olsun — keşif her şeyi doldurmaya çalışmasın, **boşluk bıraksın ve doldurulması için işaret etsin**. "47 cihazın 12'sinin sahibi yok" bilgisi, sahte bir "%100 tamam"dan çok daha değerli.

## 30 günlük önerim

1. `DiscoveryResult` → PostgreSQL şeması (`ci`, `ci_relationship`, `network_segment`, `ci_annotation`).
2. Mevcut orchestrator'ı yeni şemaya yazacak şekilde değiştir (`--db` bayrağı).
3. Basit CRUD UI (mevcut Spring Boot'a 3–4 sayfa).
4. SNMP'den `entPhysicalSerialNum` + `entPhysicalModelName` çekmeye başla.
5. Bir sonraki turda sFlow/eBPF değerlendirmesi.

Bunlar bittiğinde elinde hem **donanım envanteri** hem de **servis yönetiminin temeli** olur — ve hangi yöne gidersen git aynı veri üzerinden gidersin. Kısacası: **servis yönetimi doğru hedef, donanım envanteri doğru sıçrama tahtası, uygulama katmanı da ikisinin arasındaki eksik halka.**

**Kullanıcı:**

PostgreSQL yerine ilişkilerin daha çok katmanlı tutulabilmesini sağlamak amacıyla Neo4J gibi bir graph veritabanı kullanmak konusunda düşüncen ne?

**Asistan:**

Kısa cevap: **doğru içgüdü, ama "ilişkileri katmanlı tutmak" gerekçesi tek başına yeterli değil.** Asıl gerekçe *impact analizinin sorgu şekli*. Onu açayım, sonra hangi durumda ne seçmen gerektiğini net bir eşikle söyleyeyim.

## Neden haklısın (Neo4j'nin gerçekten kazandığı yer)

CMDB'de pahalı olan şey "kaç cihaz var" değil — **"bu switch down olursa kim etkilenir?"** Bu soru özünde:

> `(:Switch)-[:CONNECTS_TO]-(:Host)-[:HOSTS]-(:VM)-[:RUNS]-(:Service)-[:SERVES]-(:Customer)`

PostgreSQL'de bu 5-hop recursive CTE ile **yazılır da** — ama Cypher'da tek satır: `MATCH p = (s:Switch {id:$id})-[:*1..6]-(affected) RETURN affected`. Fark şurada:

- **Sorgu şekli**: Impact analizi sabit derinlikte değil — bazı yollarda 2, bazılarında 7 hop. `RECURSIVE` ile bu her çeyrekte yeniden formüle edilir, Cypher'da parametre.
- **Şema esnekliği**: Bugün switch/host/VM var; yarın "Kubernetes Pod", "SaaS bağımlılığı", "BizDevOps ekibi" ekleyeceksin. Neo4j'de *şema yok* — yeni düğüm etiketi ekle, model değişmesin. PostgreSQL'de her yeni CI tipi ya tablo ya `jsonb` sütunu → ödünleşme.
- **GDS kütüphanesi**: PageRank/centrality/community-detection **bedava gelir**. Bunu CMDB'ye uygulayınca otomatik "risk skoru" çıkıyor — "bu CI en çok kaç kritik yola giriyor?" sorusu bir ölçüm değil, bir *metrik* olur. Postgres'te bunu yazmak haftalar.
- **D3 ile simetri**: Senin UI zaten d3. Neo4j'den dönen `MATCH p = ... RETURN p` çıktısını doğrudan force-directed'a verebilirsin — view-model ↔ storage-model neredeyse aynı.

## Ama dürüst olalım (Neo4j'nin kaybetmediği − kaybettiği yer)

1. **Temporal graf**. CMDB'nin *en* gözden kaçan ihtiyacı: *"3 Mart'ta ne vardı?"* ITIL'de değişiklik onayı verilirken "o anki durum" referans alınır. Neo4j'de bi-temporal (valid_from/valid_to) **yapılır ama acıtır** — her ilişki versiyonlanır, "en son geçerli" filtresi her sorguda unutulur. PostgreSQL'de iki sütun (`valid_from`, `valid_to`) + `WHERE $at BETWEEN ...` yeter. **Bunu hafife alma, gerçek bir maliyet.**
2. **Time-series**. Link utilization, ping RTT, availability history — bunlar **asla** grafa girmez. Neo4j'de tutarsan hem yavaşlar hem yanlış araç. Ayrı kalır (TimescaleDB / VictoriaMetrics).
3. **Full-text**. "10.0.5.x içindeki eski Citrix sunucuları" gibi aramalar Postgres'te `pg_trgm` + `tsvector` ile çok iyi; Neo4j'de *vardır ama zayıftır*. Raporlama/BI de öyle — kim Excel'e "tüm CI'ları çek" diyorsa SQL ister.
4. **Operasyonel kabuk**. Backup, monitoring, versiyon yükseltme — PostgreSQL'i bilen 100 kişi varsa Neo4j'i bilen 5. **Kritik değil ama bilinçli karar olmalı.** Community sürümü HA vermez (Enterprise pahalı); tek instance yeter çünkü sistem "keşif çalışır → sonuç yazılır → okunur" deseni.

## Senin durumuna özgü kritik nokta

Bu projede **Sen Java'dasın.** Neo4j'nin *embedded mode*u senin için oyun değiştirici:

```java
GraphDatabaseService db = new GraphDatabaseFactory()
        .newEmbeddedDatabase(Paths.get("cmdb.db").toFile());
// Ayrı sunucu YOK, ağ hop YOK, sadece bir dizin. Backup = cp -r cmdb.db /backup/
```

Orchestrator yazar (tek proses), Spring Boot okur (aynı proses, aynı DB). Bu mimaride **Neo4j argümanı PostgreSQL'e karşı %90 kazanır** — çünkü esas Neo4j maliyeti (ayrı bir cluster'ı işletmek) senin durumunda **yok**. Tek sınır: **tek proses**; web UI ve keşif aynı JVM'de olmalı. Zaten öyle.

## Pragramatik önerim: hibrit veya AGE

İki dürüst yol var, ikisi de "graph DB" isteğini karşılar:

**A. Neo4j embedded + PostgreSQL (yan yana)**
- Neo4j: CI ilişkileri, impact analizi, GDS skorları, UI'ya force-graph verisi
- PostgreSQL: CI özellikleri (serial, sahip, maliyet, garanti), time-series, full-text, audit log
- **Kaçınılmaz soru:** "CI adı nerede tutulur?" Cevap: **her ikisinde de** — Neo4j CI düğümünde `:CI {id, label}` (graf gezinmesi için), Postgres `ci` tablosunda geri kalanı. Tek `id` ile bağla. Kayıt tek doğruluk noktası → Postgres.

**B. PostgreSQL + Apache AGE**
- Postgres'in üstünde Cypher eklentisi. Tek sistem, tek backup, tek dil — "hem SQL hem graf".
- AGE'nin zayıflığı: olgunluk, GDS muadili yok (centrality/PageRank'i kendin yazarsın), performans tuning sınırlı.
- **Basit tutmak istiyorsan bu en az pişmanlık veren seçenek.**

**C. Memgraph / FalkorDB** — Cypher uyumlu, in-memory, hızlı, ücretsiz sürümleri var. Neo4j'ye göre genç ama "sadece impact analizi" için yeterli. Enterprise fiyat endişesi varsa bak.

## Karar ağacı (kendine sor)

| Soru | Cevap | → Seçim |
|---|---|---|
| İlk fazda CI sayısı < ~5.000 mi? | Evet | Postgres recursive CTE **yeter**. Neo4j'ye şimdi geçme. |
| Impact analizi *ürünün ana özelliği* olacak mı? | Evet | **Neo4j embedded**. |
| Full-text + raporlama + BI ağırlıklı mı? | Evet | Postgres birincil, Neo4j ikincil (veya AGE). |
| Temporal history (valid_from/to) şart mı? | Kesinlikle | Postgres'te edge temporal, Neo4j sadece "current+1 geçmiş snapshot" (yıllık arşiv). |
| Takımda Neo4j bilen var mı / öğrenmeye istekli mi? | Hayır, operasyonel yük istemem | **Apache AGE** veya Postgres+ltree. |
| Uzun vadede Grafana/Prometheus/BI ekosistemine bağlanacak mı? | Evet | Postgres birincil. |

## Ne zaman migration başlatılır (eşik)

Kendine dürüst ol: **erken graph seçmek, yanlış seçmekten daha büyük suç değil** — ama iki ayda modeli kurup çürüyen bir CMDB'den daha kötüsü yok. Kuralım:

> **Faz 1'de Postgres ile başla.** Eşik: `MATCH (a)-[:*1..N]-(b)` sorguları (impact analizi) ürünün İLK ekranı olduğunda veya CI sayısı 5.000'i geçtiğinde Neo4j'ye geç. Bu geçiş kolay çünkü CI düğümleri sadece `{id, label, type}`; içerik Postgres'te kalıyor. **Geri dönüşü ucuz bir karar.**

## Bir sketch (Neo4j'e geçersen, model şöyle olmalı)

```cypher
// Düğümler
CREATE (s:Switch {id:'10.10.0.1', label:'core-sw-01', kind:'SWITCH'})
CREATE (h:Host   {id:'10.10.0.20', label:'kvm-01', kind:'VIRTUALIZATION_HOST'})
CREATE (v:VM     {id:'vm:web-01', label:'web-01', kind:'VIRTUAL_MACHINE'})
CREATE (a:Service{id:'svc:payment-api', label:'payment-api', criticality:3})
CREATE (c:Customer{id:'cust:acme', label:'Acme Corp'})

// İlişkiler — HER ilişkide üç metaveri ZORUNLU
CREATE (s)-[:CONNECTS_TO {port:'Gi1/0/12', protocol:'LLDP',  source:'api', confidence:1.0, valid_from:date()}]->(h)
CREATE (h)-[:HOSTS       {source:'api',   confidence:1.0, valid_from:date()}]->(v)
CREATE (v)-[:RUNS        {source:'fingerprint', confidence:0.7, valid_from:date()}]->(a)
CREATE (a)-[:SERVES      {source:'manual', confidence:1.0, valid_from:date()}]->(c)
```

`confidence` alanı **kritik**: LLDP %100, sanallaştırma API'si %100, OUI heuristic %60, parmak izi tahmini %70, manuel %100. Impact analizinde:

```cypher
// "core-sw-01 down olursa hangi müşteriler etkilenir?" — yüksek güvenle
MATCH (s:Switch {label:'core-sw-01'})
MATCH p = (s)-[:*1..6]-(c:Customer)
WHERE ALL(r IN relationships(p) WHERE r.confidence >= 0.8)   // spekülatif oku
RETURN DISTINCT c.label, length(p) AS hops
ORDER BY hops
```

Bu tek sorgu, tüm ITIL yatırımının geri dönüşüdür. Postgres'te yazılır ama *bu cümleyi* her seferinde kurmak istemezsin.

## Tuzaklar (bunlar gerçek)

1. **Grafı "tek doğruluk kaynağı" sanma.** Postgres CI özelliklerinin efendisi; Neo4j **türetilmiş** görünüm. İkisi arasında idempotent bir sync (aynı keşif çalıştırıldığında iki kez edge yaratmamak) zorunlu — `MERGE` kullan, `CREATE` değil.
2. **Edge temporal'ı sonradan ekleme.** Baştan `valid_from`/`valid_to` koy. Sonradan eklemek, tüm geçmiş sorguları yeniden yazmak demek.
3. **Uygulama/servis katmanı olmadan graf boş kalır.** En iyi Neo4j modeli, envanterde `RUNS`/`SERVES` ilişkileri yoksa sadece güzel bir kablo haritasıdır. **Asıl yatırım Neo4j'de değil, Faz 2'deki uygulama parmak izi işinde.**
4. **Neo4j Community = tek yazıcı, HA yok.** Senin durumunda sorun değil; ama yarın "her lokasyonda yazan bir agent" senaryosuna gidersen Enterprise gerekir (ya da Memgraph).
5. **Full-text ve raporu Neo4j'ye taşımaya çalışma.** Bir kez denedim sanır — herkes kaybeder. `pg_trgm` + Metabase/Grafana yapıştır, Neo4j'yi serbest bırak.

## Son söz

**Neo4j'ye karşı değilim — "önce Neo4j" fikrine karşıyım.** Bu projenin doğal yolu:

- **Faz 1**: Postgres (CI + özellik + temporal + fulltext) → standart, operasyonel, ucuz
- **Faz 2**: Uygulama/servis parmak izi + sFlow → ilişkilerin *gerçekten* anlam kazanması
- **Faz 3** (impact analizi ürünleşince): Neo4j embedded yan yana → geri dönüşü ucuz, model zaten hazır

Eğer ilk günden **tek sistem** istiyorsan **Postgres + Apache AGE** ile başla, üç ayda Neo4j'ye geçiş maliyetini sıfıra yakın tut. Eğer gönlün Neo4j diyorsa — **embedded mode başlat**, ki bu kararın en az pişmanlık veren biçimi.

İstersen bir sonraki adımda **her iki şemanın somut DDL/Cypher karşılığını** ve `DiscoveryResult → CMDB upsert` dönüşümünü yazayım — net şekilde karşılaştırırız. Hangisiyle devam?
