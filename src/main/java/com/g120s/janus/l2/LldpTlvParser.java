package com.g120s.janus.l2;

import java.nio.charset.StandardCharsets;

public final class LldpTlvParser {
    private LldpTlvParser() {}

    public static void parse(byte[] packet, int offset, int length, NeighborRecord record) {
        if (offset < 0 || length < 0 || offset > packet.length - length) return;
        int end = offset + length;
        int i = offset;
        while (i + 2 <= end) {
            int header = u16(packet, i);
            int type = header >>> 9;
            int tlvLength = header & 0x1ff;
            i += 2;
            if (i + tlvLength > end) return;
            switch (type) {
                case 0 -> { return; }
                case 1 -> parseId(packet, i, tlvLength, record, true);
                case 2 -> parseId(packet, i, tlvLength, record, false);
                case 3 -> {
                    if (tlvLength == 2) record.ttl = u16(packet, i);
                }
                case 4 -> record.remotePortDesc = text(packet, i, tlvLength);
                case 5 -> record.remoteSystemName = text(packet, i, tlvLength);
                case 6 -> record.remoteSystemDesc = text(packet, i, tlvLength);
                case 7 -> parseCapabilities(packet, i, tlvLength, record);
                case 8 -> parseManagementAddress(packet, i, tlvLength, record);
                case 127 -> parseOrganizationTlv(packet, i, tlvLength, record);
                default -> { }
            }
            i += tlvLength;
        }
    }

    private static void parseId(byte[] packet, int offset, int length,
                                NeighborRecord record, boolean chassis) {
        if (length < 1) return;
        int subtype = packet[offset] & 0xff;
        int valueOffset = offset + 1;
        int valueLength = length - 1;
        String id = subtype == 4 && valueLength == 6 || subtype == 3 && valueLength == 6
                ? mac(packet, valueOffset)
                : subtype == 5 && valueLength >= 5 && (packet[valueOffset] & 0xff) == 1
                ? ipv4(packet, valueOffset + 1)
                : text(packet, valueOffset, valueLength);
        if (chassis) {
            record.remoteChassisType = switch (subtype) {
                case 4 -> "mac";
                case 5 -> "network-address";
                case 7 -> "local";
                default -> "subtype-" + subtype;
            };
            record.remoteChassisId = id;
        } else {
            record.remotePortType = switch (subtype) {
                case 3 -> "mac";
                case 5 -> "if-name";
                case 7 -> "local";
                default -> "subtype-" + subtype;
            };
            record.remotePortId = id;
        }
    }

    private static void parseCapabilities(byte[] packet, int offset, int length,
                                          NeighborRecord record) {
        if (length < 4) return;
        int enabled = u16(packet, offset + 2);
        if ((enabled & 0x0002) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.REPEATER);
        if ((enabled & 0x0004) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.BRIDGE);
        if ((enabled & 0x0008) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.WLAN_AP);
        if ((enabled & 0x0010) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.ROUTER);
        if ((enabled & 0x0020) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.TELEPHONE);
        if ((enabled & 0x0040) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.DOCSIS);
        if ((enabled & 0x0080) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.STATION);
        if ((enabled & 0x0100) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.C_VLAN);
        if ((enabled & 0x0200) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.S_VLAN);
        if ((enabled & 0x0400) != 0) record.remoteCapabilities.add(NeighborRecord.Capability.TWO_PORT_BRIDGE);
    }

    private static void parseManagementAddress(byte[] packet, int offset, int length,
                                               NeighborRecord record) {
        int end = offset + length;
        int i = offset;
        if (i >= end) return;
        int addressLength = packet[i++] & 0xff;
        if (addressLength < 1 || i + addressLength > end) return;
        int subtype = packet[i++] & 0xff;
        int rawLength = addressLength - 1;
        if (subtype == 1 && rawLength == 4) record.remoteMgmtIps.add(ipv4(packet, i));
        if (subtype == 2 && rawLength == 16) record.remoteMgmtIps.add(ipv6(packet, i));
        i += rawLength;
        if (i + 5 > end) return;
        i += 5;
        if (i >= end) return;
        int oidLength = packet[i++] & 0xff;
        if (i + oidLength > end) return;
    }

    private static void parseOrganizationTlv(byte[] packet, int offset, int length,
                                             NeighborRecord record) {
        if (length < 4) return;
        int oui = ((packet[offset] & 0xff) << 16)
                | ((packet[offset + 1] & 0xff) << 8)
                | (packet[offset + 2] & 0xff);
        int subtype = packet[offset + 3] & 0xff;
        if (oui == 0x00120f && subtype == 1 && length >= 6) {
            record.remoteNativeVlan = u16(packet, offset + 4);
        } else if (oui == 0x00120f && subtype == 3 && length >= 6) {
            record.remoteVlanId = u16(packet, offset + 4);
            record.remoteVlanName = text(packet, offset + 6, length - 6);
        } else if (oui == 0x0012bb && subtype == 1) {
            record.extras.put("med", "capabilities");
        } else if (oui == 0x0012bb && subtype == 3) {
            record.extras.put("med", "location");
        } else if (oui == 0x0012bb && subtype == 4) {
            record.extras.put("med", "poe");
        }
    }

    private static int u16(byte[] packet, int offset) {
        return ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff);
    }

    static String mac(byte[] bytes, int offset) {
        StringBuilder value = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) value.append(':');
            value.append("%02x".formatted(bytes[offset + i] & 0xff));
        }
        return value.toString();
    }

    static String ipv4(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) + "." + (bytes[offset + 1] & 0xff) + "."
                + (bytes[offset + 2] & 0xff) + "." + (bytes[offset + 3] & 0xff);
    }

    static String ipv6(byte[] bytes, int offset) {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) value.append(':');
            value.append("%02x%02x".formatted(bytes[offset + i] & 0xff, bytes[offset + i + 1] & 0xff));
        }
        return value.toString();
    }

    static String text(byte[] bytes, int offset, int length) {
        int end = offset + length;
        while (end > offset && bytes[end - 1] == 0) end--;
        return new String(bytes, offset, end - offset, StandardCharsets.UTF_8);
    }
}
