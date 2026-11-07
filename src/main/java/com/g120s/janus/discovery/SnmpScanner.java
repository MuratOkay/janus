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
            if (descr == null) return null;   // no SNMP / unreachable

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
        return vb.getVariable().isException() ? null : vb.getVariable().toString();
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
            if (!vb.getOid().startsWith(col) || vb.getVariable().isException()) break;
            out.add(vb.getVariable().toString());
            cur = vb.getOid();
        }
        return out;
    }
}