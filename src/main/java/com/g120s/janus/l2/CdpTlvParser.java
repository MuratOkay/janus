package com.g120s.janus.l2;

public final class CdpTlvParser {
    private CdpTlvParser() {}

    public static void parse(byte[] packet, int offset, int length, NeighborRecord record) {
        if (offset < 0 || length < 4 || offset > packet.length - length) return;
        int end = offset + length;
        int i = offset + 4;
        while (i + 4 <= end) {
            int type = u16(packet, i);
            int tlvLength = u16(packet, i + 2);
            if (tlvLength < 4 || i + tlvLength > end) return;
            int valueOffset = i + 4;
            int valueLength = tlvLength - 4;
            switch (type) {
                case 0x0001 -> record.remoteChassisId = LldpTlvParser.text(packet, valueOffset, valueLength);
                case 0x0002 -> parseAddressList(packet, valueOffset, valueLength, record);
                case 0x0003 -> record.remotePortId = LldpTlvParser.text(packet, valueOffset, valueLength);
                case 0x0004 -> parseCapabilities(packet, valueOffset, valueLength, record);
                case 0x0005 -> record.remoteSystemDesc = LldpTlvParser.text(packet, valueOffset, valueLength);
                case 0x0006 -> record.extras.put("platform", LldpTlvParser.text(packet, valueOffset, valueLength));
                case 0x0009 -> record.extras.put("vtpDomain", LldpTlvParser.text(packet, valueOffset, valueLength));
                case 0x000a -> {
                    if (valueLength == 2) record.remoteNativeVlan = u16(packet, valueOffset);
                }
                case 0x0014 -> record.remoteSystemName = LldpTlvParser.text(packet, valueOffset, valueLength);
                case 0x0016 -> parseAddressList(packet, valueOffset, valueLength, record);
                default -> { }
            }
            i += tlvLength;
        }
    }

    private static void parseCapabilities(byte[] packet, int offset, int length,
                                          NeighborRecord record) {
        if (length != 4) return;
        long flags = ((long) (packet[offset] & 0xff) << 24)
                | ((long) (packet[offset + 1] & 0xff) << 16)
                | ((long) (packet[offset + 2] & 0xff) << 8)
                | (packet[offset + 3] & 0xffL);
        if ((flags & 0x01) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.ROUTER);
        if ((flags & 0x02) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.BRIDGE);
        if ((flags & 0x08) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.SWITCH);
        if ((flags & 0x10) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.STATION);
        if ((flags & 0x40) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.TELEPHONE);
    }

    private static void parseAddressList(byte[] packet, int offset, int length,
                                         NeighborRecord record) {
        int end = offset + length;
        if (offset >= end) return;
        int count = packet[offset] & 0xff;
        int i = offset + 1;
        for (int entry = 0; entry < count; entry++) {
            if (i + 2 > end) return;
            int protocolType = packet[i++] & 0xff;
            int protocolLength = packet[i++] & 0xff;
            if (i + protocolLength + 2 > end) return;
            boolean ipv4 = protocolType == 1 && protocolLength == 1
                    && (packet[i] & 0xff) == 0xcc;
            i += protocolLength;
            int addressLength = u16(packet, i);
            i += 2;
            if (i + addressLength > end) return;
            if (ipv4 && addressLength == 4) {
                record.remoteMgmtIps.add(LldpTlvParser.ipv4(packet, i));
            }
            i += addressLength;
        }
    }

    private static int u16(byte[] packet, int offset) {
        return ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff);
    }
}
