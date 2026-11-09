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

    /** ipRouteType `invalid`, per RFC 1213 — the row is not a usable route. */
    static final String ROUTE_TYPE_INVALID = "2";

    public record SnmpResult(String sysDescr, String sysName, String sysLoc,
                             List<String> ipAddresses,
                             Map<String,String> ifMasks,
                             Map<String,String> routes,
                             Map<String,String> routeMasks,
                             Map<String,String> routeTypes,
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

            snmp.close();
            return new SnmpResult(descr, name, loc, List.copyOf(addrs.keySet()),
                    ifMasks, routes, routeMasks, routeTypes, arps);
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
            String key = indexToIp(col, vb.getOid());
            if (key != null) out.put(key, vb.getVariable().toString());
            cur = vb.getOid();
        }
        return out;
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