package com.g120s.janus.discovery;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.net.*;
import java.util.*;
import java.util.concurrent.TimeoutException;

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
                    .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .dstProtocolAddr(t)
                    .build();
            EthernetPacket pkt = new EthernetPacket.Builder()
                    .srcAddr(MacAddress.getByAddress(localMacBytes))
                    .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
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