package com.g120s.janus.l2;

import org.pcap4j.core.*;

import java.util.*;
import java.util.concurrent.TimeoutException;

public final class NeighborSniffer {
    public record CaptureOptions(String iface, int durationMs) {}

    private NeighborSniffer() {}

    public static List<NeighborRecord> capture(CaptureOptions options) throws Exception {
        if (options.durationMs() <= 0) throw new IllegalArgumentException("Dinleme süresi pozitif olmalı");
        PcapNetworkInterface networkInterface = Pcaps.getDevByName(options.iface());
        if (networkInterface == null) throw new IllegalArgumentException("Arayüz bulunamadı: " + options.iface());
        String localMac = networkInterface.getLinkLayerAddresses().isEmpty()
                ? null : LldpTlvParser.mac(networkInterface.getLinkLayerAddresses().get(0).getAddress(), 0);

        PcapHandle handle = networkInterface.openLive(65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100);
        Map<String, NeighborRecord> neighbors = new LinkedHashMap<>();
        try {
            handle.setFilter("ether proto 0x88cc or ether proto 0x2000 or (vlan and ether proto 0x88cc) "
                    + "or (vlan and ether proto 0x2000) or llc", BpfProgram.BpfCompileMode.OPTIMIZE);
            long stopAt = System.currentTimeMillis() + options.durationMs();
            while (System.currentTimeMillis() < stopAt) {
                byte[] raw;
                try {
                    raw = handle.getNextRawPacketEx();
                } catch (TimeoutException ignored) {
                    continue;
                }
                if (raw == null || raw.length < 14) continue;

                int etherType = u16(raw, 12);
                int offset = 14;
                Integer vlan = null;
                int tagDepth = 0;
                while ((etherType == 0x8100 || etherType == 0x88a8) && offset + 4 <= raw.length) {
                    vlan = u16(raw, offset) & 0x0fff;
                    etherType = u16(raw, offset + 2);
                    offset += 4;
                    if (++tagDepth > 3) break;
                }

                NeighborRecord record = new NeighborRecord();
                record.timestamp = System.currentTimeMillis();
                record.localIface = options.iface();
                record.localMac = localMac;
                record.localVlan = vlan;
                if (etherType == 0x88cc) {
                    record.protocol = NeighborRecord.Protocol.LLDP;
                    LldpTlvParser.parse(raw, offset, raw.length - offset, record);
                } else if (etherType == 0x2000) {
                    record.protocol = NeighborRecord.Protocol.CDP;
                    CdpTlvParser.parse(raw, offset, raw.length - offset, record);
                } else if (etherType <= 1500 && offset + 8 <= raw.length
                        && (raw[offset] & 0xff) == 0xaa
                        && (raw[offset + 1] & 0xff) == 0xaa
                        && (raw[offset + 2] & 0xff) == 0x03
                        && u16(raw, offset + 6) == 0x2000
                        && u24(raw, offset + 3) == 0x00000c) {
                    record.protocol = NeighborRecord.Protocol.CDP;
                    CdpTlvParser.parse(raw, offset + 8, Math.min(etherType - 8, raw.length - offset - 8), record);
                } else {
                    continue;
                }
                if (record.remoteChassisId == null && record.remoteSystemName == null
                        && record.remotePortId == null) continue;
                String key = record.protocol + "|" + record.remoteChassisId + "|"
                        + record.remotePortId + "|" + record.localVlan;
                neighbors.put(key, record);
            }
        } finally {
            handle.close();
        }
        return new ArrayList<>(neighbors.values());
    }

    private static int u16(byte[] packet, int offset) {
        return ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff);
    }

    private static int u24(byte[] packet, int offset) {
        return ((packet[offset] & 0xff) << 16)
                | ((packet[offset + 1] & 0xff) << 8)
                | (packet[offset + 2] & 0xff);
    }
}
