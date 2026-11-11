package com.g120s.janus.discovery;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.*;

public final class SnmpScanner {

    private static final OID SYS_DESCR = new OID("1.3.6.1.2.1.1.1.0");
    private static final OID SYS_NAME  = new OID("1.3.6.1.2.1.1.5.0");
    private static final OID SYS_LOC   = new OID("1.3.6.1.2.1.1.6.0");
    // ipAddrTable is indexed by address, so the row index is the address itself.
    private static final OID IP_ADDR   = new OID("1.3.6.1.2.1.4.20.1.1");   // ipAdEntAddr
    private static final OID IP_MASK   = new OID("1.3.6.1.2.1.4.20.1.3");   // ipAdEntNetMask
    // ipRouteTable is indexed by destination; the mask lives in a separate column.
    private static final OID ROUTE_NH  = new OID("1.3.6.1.2.1.4.21.1.7");    // ipRouteNextHop
    private static final OID ROUTE_TYPE= new OID("1.3.6.1.2.1.4.21.1.8");    // ipRouteType
    private static final OID ROUTE_MASK= new OID("1.3.6.1.2.1.4.21.1.11");   // ipRouteMask
    private static final OID ARP_MAC   = new OID("1.3.6.1.2.1.4.22.1.2");    // ipNetToMediaPhysAddress
    // Layer-2 / VLAN tables, for locating a host on a switch port and per VLAN.
    private static final OID IP_IFINDEX = new OID("1.3.6.1.2.1.4.20.1.2");   // ipAdEntIfIndex
    private static final OID IF_NAME    = new OID("1.3.6.1.2.1.2.2.1.2");     // ifName
    private static final OID IF_ALIAS   = new OID("1.3.6.1.2.1.31.1.1.1.18"); // ifAlias (operator label)
    private static final OID BRIDGE_MAC = new OID("1.3.6.1.2.1.17.4.3.1.1");  // dot1dTpFdbAddress
    private static final OID BRIDGE_PORT= new OID("1.3.6.1.2.1.17.4.3.1.2");  // dot1dTpFdbPort
    private static final OID BRIDGE_IF  = new OID("1.3.6.1.2.1.17.1.4.1.2");  // dot1dBasePortIfIndex
    private static final OID QB_FDB_PORT= new OID("1.3.6.1.2.1.17.7.1.2.2.1.2"); // dot1qTpFdbPort
    private static final OID QB_VLAN_NAME = new OID("1.3.6.1.2.1.17.7.1.4.3.1.1"); // dot1qVlanStaticName

    /** ipRouteType `invalid`, per RFC 1213 — the row is not a usable route. */
    static final String ROUTE_TYPE_INVALID = "2";

    // HOST-RESOURCES-MIB (RFC 2790): CPU, memory and filesystem inventory.
    static final OID HR_MEMORY_SIZE   = new OID("1.3.6.1.2.1.25.2.2.0");    // hrMemorySize (KB)
    static final OID HR_STORAGE_TYPE  = new OID("1.3.6.1.2.1.25.2.3.1.2");  // hrStorageType
    static final OID HR_STORAGE_DESCR = new OID("1.3.6.1.2.1.25.2.3.1.3");  // hrStorageDescr
    static final OID HR_STORAGE_UNITS = new OID("1.3.6.1.2.1.25.2.3.1.4");  // hrStorageAllocationUnits
    static final OID HR_STORAGE_SIZE  = new OID("1.3.6.1.2.1.25.2.3.1.5");  // hrStorageSize
    static final OID HR_STORAGE_USED  = new OID("1.3.6.1.2.1.25.2.3.1.6");  // hrStorageUsed
    static final OID HR_DEVICE_TYPE   = new OID("1.3.6.1.2.1.25.3.2.1.2");  // hrDeviceType
    static final OID HR_DEVICE_DESCR  = new OID("1.3.6.1.2.1.25.3.2.1.3");  // hrDeviceDescr
    static final OID HR_PROCESSOR_LOAD= new OID("1.3.6.1.2.1.25.3.3.1.2");  // hrProcessorLoad
    static final OID HR_FS_MOUNT      = new OID("1.3.6.1.2.1.25.3.8.1.2");  // hrFSMountPoint
    static final OID HR_FS_STORAGE    = new OID("1.3.6.1.2.1.25.3.8.1.7");  // hrFSStorageIndex

    /** {@code hrStorageFixedDisk}; note tmpfs shares this type, see HardwareProbe. */
    static final String HR_TYPE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4";
    /** {@code hrDeviceProcessor} — filters CPUs out of a table that also holds NICs. */
    static final String HR_DEVICE_PROCESSOR = "1.3.6.1.2.1.25.3.1.3";

    /** The raw HOST-RESOURCES tables needed to build a hardware inventory. */
    public record HostResources(String memorySizeKb,
                                Map<String,String> storageTypes,
                                Map<String,String> storageDescriptions,
                                Map<String,String> storageAllocationUnits,
                                Map<String,String> storageSizes,
                                Map<String,String> storageUsed,
                                Map<String,String> deviceTypes,
                                Map<String,String> deviceDescriptions,
                                Map<String,String> processorLoads,
                                Map<String,String> fsMountPoints,
                                Map<String,String> fsStorageIndexes) {

        /** True when the device answered nothing useful, e.g. no HOST-RESOURCES support. */
        public boolean isEmpty() {
            return memorySizeKb == null && storageSizes.isEmpty()
                    && processorLoads.isEmpty() && fsMountPoints.isEmpty();
        }
    }

    /**
     * Reads the HOST-RESOURCES-MIB tables. Returns {@code null} when the agent does
     * not implement them, which is the common case for consumer network gear.
     */
    public static HostResources hostResources(String host, String community, int timeoutMs)
            throws Exception {
        try (TransportMapping<?> transport = new DefaultUdpTransportMapping()) {
            transport.listen();
            Snmp snmp = new Snmp(transport);
            CommunityTarget<Address> t = new CommunityTarget<>();
            t.setCommunity(new OctetString(community));
            t.setAddress(GenericAddress.parse("udp:" + host + "/161"));
            t.setRetries(1);
            t.setTimeout(timeoutMs);
            t.setVersion(SnmpConstants.version2c);

            // hrMemorySize is a scalar; if it is absent the agent has no HOST-RESOURCES
            // support at all, so there is no point walking the tables.
            String memory = get(snmp, t, HR_MEMORY_SIZE);
            if (memory == null) {
                snmp.close();
                return null;
            }

            HostResources resources = new HostResources(
                    memory,
                    walkIntegerIndexed(snmp, t, HR_STORAGE_TYPE),
                    walkIntegerIndexed(snmp, t, HR_STORAGE_DESCR),
                    walkIntegerIndexed(snmp, t, HR_STORAGE_UNITS),
                    walkIntegerIndexed(snmp, t, HR_STORAGE_SIZE),
                    walkIntegerIndexed(snmp, t, HR_STORAGE_USED),
                    walkIntegerIndexed(snmp, t, HR_DEVICE_TYPE),
                    walkIntegerIndexed(snmp, t, HR_DEVICE_DESCR),
                    walkIntegerIndexed(snmp, t, HR_PROCESSOR_LOAD),
                    walkIntegerIndexed(snmp, t, HR_FS_MOUNT),
                    walkIntegerIndexed(snmp, t, HR_FS_STORAGE));
            snmp.close();
            return resources;
        }
    }

    public record SnmpResult(String sysDescr, String sysName, String sysLoc,
                             List<String> ipAddresses,
                             Map<String,String> ifMasks,
                             Map<String,String> routes,
                             Map<String,String> routeMasks,
                             Map<String,String> routeTypes,
                             Map<String,String> arpTable,
                             Map<String,String> ifIndexes,
                             Map<String,String> ifNames,
                             Map<String,String> ifAliases,
                             Map<String,String> bridgePorts,
                             Map<String,String> bridgePortIfIndexes,
                             Map<String,String> vlanBridgePorts,
                             Map<String,String> vlanNames) {}

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
            if (descr == null) return null;   // no SNMP / unreachable

            String name = get(snmp, t, SYS_NAME);
            String loc  = get(snmp, t, SYS_LOC);

            // Directly attached networks: address -> netmask. This is the most
            // authoritative view of a router's own subnets.
            Map<String,String> ifMasks = walkIndexed(snmp, t, IP_MASK);
            Map<String,String> addrs   = walkIndexed(snmp, t, IP_ADDR);

            // Rows are paired by their table index rather than by position, so a
            // partially populated column can never shift values onto the wrong route.
            Map<String,String> routeMasks = walkIndexed(snmp, t, ROUTE_MASK);
            Map<String,String> routeTypes = walkIndexed(snmp, t, ROUTE_TYPE);
            Map<String,String> routes     = walkIndexed(snmp, t, ROUTE_NH);

            // ipNetToMediaTable is indexed by ifIndex + address, so the address is
            // recovered from the tail of the index.
            Map<String,String> arps = walkIndexed(snmp, t, ARP_MAC);

            // Interface inventory: index is a plain ifIndex.
            Map<String,String> ifIndexes  = walkIndexed(snmp, t, IP_IFINDEX);
            Map<String,String> ifNames    = walkIndexed(snmp, t, IF_NAME);
            Map<String,String> ifAliases  = walkIndexed(snmp, t, IF_ALIAS);

            // Bridge forwarding tables: which switch port holds which MAC. The plain
            // table is VLAN-agnostic; the Q-BRIDGE one is indexed by VLAN + MAC and is
            // what makes per-VLAN host location possible.
            Map<String,String> bridgePorts     = walkIndexed(snmp, t, BRIDGE_PORT);
            Map<String,String> bridgePortIfIdx = walkIndexed(snmp, t, BRIDGE_IF);
            Map<String,String> vlanBridgePorts = walkIndexed(snmp, t, QB_FDB_PORT);
            Map<String,String> vlanNames       = walkIndexed(snmp, t, QB_VLAN_NAME);

            snmp.close();
            return new SnmpResult(descr, name, loc, List.copyOf(addrs.keySet()),
                    ifMasks, routes, routeMasks, routeTypes, arps,
                    ifIndexes, ifNames, ifAliases,
                    bridgePorts, bridgePortIfIdx, vlanBridgePorts, vlanNames);
        }
    }

    private static String get(Snmp snmp, Target<Address> t, OID oid) throws Exception {
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(oid));
        pdu.setType(PDU.GET);
        ResponseEvent<Address> r = snmp.send(pdu, t);
        if (r == null || r.getResponse() == null || r.getResponse().getErrorStatus() != 0) return null;
        VariableBinding vb = r.getResponse().get(0);
        return vb.getVariable().isException() ? null : vb.getVariable().toString();
    }

    /**
     * Walks a table column and pairs each row's index with its value. The index is
     * decoded back into a dotted address where the table is IP-indexed, which is
     * what keeps a destination and its mask aligned.
     */
    private static Map<String,String> walkIndexed(Snmp snmp, Target<Address> t, OID col) throws Exception {
        return walkIntegerKeyed(snmp, t, col, false);
    }

    /**
     * Walks a column keyed by a plain integer row index, as HOST-RESOURCES-MIB tables
     * are. Reusing the address decoder for these would mislabel every row: a storage
     * index of {@code 36} has nothing to do with {@code 0.0.0.36}.
     */
    private static Map<String,String> walkIntegerIndexed(Snmp snmp, Target<Address> t, OID col)
            throws Exception {
        return walkIntegerKeyed(snmp, t, col, true);
    }

    private static Map<String,String> walkIntegerKeyed(Snmp snmp, Target<Address> t, OID col,
                                                       boolean integerIndex) throws Exception {
        Map<String,String> out = new LinkedHashMap<>();
        OID cur = col;
        while (true) {
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(cur));
            pdu.setType(PDU.GETNEXT);
            ResponseEvent<Address> r = snmp.send(pdu, t);
            if (r == null || r.getResponse() == null) break;
            VariableBinding vb = r.getResponse().get(0);
            if (!vb.getOid().startsWith(col) || vb.getVariable().isException()) break;
            String key = integerIndex
                    ? singleIntKey(suffixOf(col, vb.getOid()))
                    : indexKey(col, vb.getOid());
            if (key != null) out.put(key, vb.getVariable().toString());
            cur = vb.getOid();
        }
        return out;
    }

    /** Is this column indexed by an IPv4 address? */
    private static boolean isIpIndexed(OID column) {
        return column.equals(IP_ADDR) || column.equals(IP_MASK) || column.equals(IP_IFINDEX)
                || column.equals(ARP_MAC) || column.equals(ROUTE_NH)
                || column.equals(ROUTE_TYPE) || column.equals(ROUTE_MASK);
    }

    /**
     * Turns a row OID into the key that pairs it with the other columns of the same
     * table. Each table family is indexed differently, and using the wrong decoder
     * silently mislabels every row.
     */
    static String indexKey(OID column, OID row) {
        int[] suffix = suffixOf(column, row);
        if (suffix == null) return null;
        if (isIpIndexed(column)) return ipFromSuffix(suffix);
        // dot1qTpFdbPort is indexed by VLAN followed by the MAC.
        if (column.equals(QB_FDB_PORT)) return vlanMacKey(suffix);
        if (column.equals(BRIDGE_PORT) || column.equals(BRIDGE_MAC)) return macFromSuffix(suffix);
        // ifName, ifAlias, dot1dBasePortIfIndex and dot1qVlanStaticName use a single
        // integer index (ifIndex, bridge port and VLAN respectively).
        return singleIntKey(suffix);
    }

    /** Sub-identifiers following the column in a row OID; {@code null} if none. */
    static int[] suffixOf(OID column, OID row) {
        if (column == null || row == null || row.size() <= column.size()) return null;
        int[] suffix = new int[row.size() - column.size()];
        for (int i = 0; i < suffix.length; i++) suffix[i] = row.get(column.size() + i);
        return suffix;
    }

    /** A single trailing integer, such as an ifIndex or a VLAN id. */
    static String singleIntKey(int[] suffix) {
        if (suffix == null || suffix.length < 1) return null;
        return String.valueOf(suffix[suffix.length - 1]);
    }

    /** Six trailing octets as a colon-separated MAC address. */
    static String macFromSuffix(int[] suffix) {
        if (suffix == null || suffix.length < 6) return null;
        int offset = suffix.length - 6;
        StringBuilder mac = new StringBuilder(17);
        for (int i = offset; i < suffix.length; i++) {
            int octet = suffix[i];
            if (octet < 0 || octet > 255) return null;
            if (mac.length() > 0) mac.append(':');
            mac.append(String.format("%02x", octet));
        }
        return mac.toString();
    }

    /** {@code <vlan>:<mac>} key for the Q-BRIDGE forwarding table. */
    static String vlanMacKey(int[] suffix) {
        if (suffix == null || suffix.length < 7) return null;
        String mac = macFromSuffix(suffix);
        if (mac == null) return null;
        return suffix[suffix.length - 7] + ":" + mac;
    }

    /** VLAN id parsed out of a {@link #vlanMacKey} value. */
    static Integer vlanOfKey(String key) {
        if (key == null) return null;
        int separator = key.indexOf(':');
        if (separator <= 0) return null;
        try {
            return Integer.parseInt(key.substring(0, separator));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** MAC parsed out of a {@link #vlanMacKey} value. */
    static String macOfKey(String key) {
        if (key == null) return null;
        int separator = key.indexOf(':');
        // A bare MAC also contains colons, so only strip a numeric prefix.
        if (separator > 0) {
            try {
                Integer.parseInt(key.substring(0, separator));
                return key.substring(separator + 1);
            } catch (NumberFormatException ignored) {
                return key;
            }
        }
        return key;
    }

    /** Decodes the table index that follows {@code column} into a dotted address. */
    static String indexToIp(OID column, OID row) {
        if (row.size() <= column.size()) return null;
        int[] suffix = new int[row.size() - column.size()];
        for (int i = 0; i < suffix.length; i++) suffix[i] = row.get(column.size() + i);
        return ipFromSuffix(suffix);
    }

    /**
     * Recovers the address from a table index. A four element suffix is the address
     * itself; longer suffixes (ipNetToMediaTable prefixes the ifIndex) carry it in
     * the last four sub-identifiers.
     */
    static String ipFromSuffix(int[] suffix) {
        if (suffix == null || suffix.length < 4) return null;
        int offset = suffix.length - 4;
        for (int i = offset; i < suffix.length; i++) {
            if (suffix[i] < 0 || suffix[i] > 255) return null;
        }
        return suffix[offset] + "." + suffix[offset + 1] + "."
                + suffix[offset + 2] + "." + suffix[offset + 3];
    }
}