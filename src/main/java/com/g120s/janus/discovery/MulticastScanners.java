package com.g120s.janus.discovery;

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
                    DClass.IN, 0, Name.fromString("_services._dns-sd._udp.local.")), Section.QUESTION);
            byte[] out = q.toWire();
            s.send(new DatagramPacket(out, out.length, group, 5353));

            long end = System.currentTimeMillis() + durationMs;
            byte[] buf = new byte[4096];
            while (System.currentTimeMillis() < end) {
                try {
                    DatagramPacket in = new DatagramPacket(buf, buf.length);
                    s.receive(in);
                    byte[] responseBytes = Arrays.copyOfRange(
                            in.getData(), in.getOffset(), in.getOffset() + in.getLength());
                    Message resp = new Message(responseBytes);
                    for (org.xbill.DNS.Record r : resp.getSection(Section.ANSWER)) {
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