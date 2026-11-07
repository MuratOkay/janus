package com.g120s.janus.discovery;

import org.xbill.DNS.*;
import java.net.*;
import java.util.*;

public final class MulticastScanners {

    /** mDNS scan result: live addresses and the host names found. */
    public record MdnsResult(Set<InetAddress> addresses, Map<InetAddress, String> names) {}

    /** mDNS: queries _services._dns-sd._udp.local and common services, returns the responding IPs. */
    public static Set<InetAddress> mdns(int durationMs) throws Exception {
        return mdnsWithNames(durationMs).addresses();
    }

    /** Runs an mDNS scan and returns both the live addresses and the parsed host names. */
    public static MdnsResult mdnsWithNames(int durationMs) throws Exception {
        Set<InetAddress> seen = new HashSet<>();
        Map<InetAddress, String> names = new HashMap<>();
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
                        // Collect host name (.local) candidates
                        String candidate = switch (r) {
                            case SRVRecord srv -> srv.getTarget().toString(true);
                            case PTRRecord ptr -> ptr.getTarget().toString(true);
                            case ARecord _ -> r.getName().toString(true);
                            default -> null;
                        };
                        if (candidate != null && !candidate.startsWith("_")) {
                            String normalized = NameResolver.normalize(candidate);
                            if (normalized != null && normalized.contains(".")) {
                                names.putIfAbsent(in.getAddress(), stripLocal(normalized));
                            }
                        }
                        if (r instanceof PTRRecord || r instanceof SRVRecord) {
                            // also treat the source IP of every answer as live
                            seen.add(in.getAddress());
                        }
                    }
                    seen.add(in.getAddress());
                } catch (SocketTimeoutException ignored) { }
            }
            s.leaveGroup(new InetSocketAddress(group, 5353),
                    NetworkInterface.getByInetAddress(InetAddress.getLocalHost()));
        }
        return new MdnsResult(seen, names);
    }

    /** Strips the ".local" suffix; "printer.local" -> "printer". */
    private static String stripLocal(String name) {
        String value = name;
        if (value.endsWith(".local")) value = value.substring(0, value.length() - ".local".length());
        return value.isEmpty() ? name : value;
    }

    /** SSDP (UPnP): devices that answer an M-SEARCH. Routers, NAS, smart TVs, IoT. */
    public static Set<InetAddress> ssdp(int durationMs) throws Exception {
        return ssdpWithHeaders(durationMs).keySet();
    }

    /** Runs an SSDP scan and returns the response headers for each device (for name inference). */
    public static Map<InetAddress, String> ssdpWithHeaders(int durationMs) throws Exception {
        Map<InetAddress, String> responses = new LinkedHashMap<>();
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
                    String headers = new String(buf, p.getOffset(), p.getLength(),
                            java.nio.charset.StandardCharsets.ISO_8859_1);
                    responses.putIfAbsent(p.getAddress(), headers);
                } catch (SocketTimeoutException ignored) { }
            }
        }
        return responses;
    }

    /** NetBIOS Node Status (UDP 137) — provides name and MAC information for Windows clients. */
    public static Map<InetAddress, String> netbios(InetAddress target, int timeoutMs) {
        Map<InetAddress, String> out = new HashMap<>();
        String name = netbiosName(target, timeoutMs);
        if (name != null) out.put(target, name);
        return out;
    }

    /**
     * Parses a NetBIOS Node Status response and returns the most likely computer name.
     *
     * <p>Response layout: header(12) + NB name(34) + type(2) + class(2) + ttl(4)
     * + rdlength(2) = 56; then a name count(1) followed by records of 18 bytes each
     * (15 name + 1 suffix + 2 flags).
     *
     * <p>Preference: suffix 0x00 (workstation/computer name) and a non-group record.
     */
    public static String netbiosName(InetAddress target, int timeoutMs) {
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

            int len = p.getLength();
            if (len < 57) return null;
            int count = buf[56] & 0xFF;
            String fallback = null;

            for (int i = 0; i < count; i++) {
                int base = 57 + i * 18;
                if (base + 15 > len) break;

                String raw = new String(buf, base, 15, java.nio.charset.StandardCharsets.US_ASCII);
                String name = raw.replace('\u0000', ' ').trim();
                if (name.isEmpty()) continue;

                int suffix = buf[base + 15] & 0xFF;
                int flags = ((buf[base + 16] & 0xFF) << 8) | (buf[base + 17] & 0xFF);
                boolean group = (flags & 0x8000) != 0;

                // Suffix 0x00 = computer name, 0x20 = file sharing service
                if (suffix == 0x00 && !group) {
                    return name;
                }
                if (fallback == null && !group && (suffix == 0x20 || suffix == 0x03)) {
                    fallback = name;
                }
            }
            return fallback;
        } catch (Exception ignored) {
            return null;
        }
    }
}