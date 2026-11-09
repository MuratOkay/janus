package com.g120s.janus.discovery;

import com.g120s.janus.model.Device;
import com.g120s.janus.model.DiscoveryResult;
import org.junit.jupiter.api.Test;
import org.snmp4j.smi.OID;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * L2 discovery depends on decoding each table's index correctly. The bridge tables
 * are indexed by MAC and by VLAN+MAC, not by address, so a single shared decoder
 * would silently mislabel every row.
 */
class L2DiscoveryTests {

    @Test
    void interfaceTablesAreIndexedByIfIndex() {
        OID ifName = new OID("1.3.6.1.2.1.2.2.1.2");
        assertEquals("7", SnmpScanner.indexKey(ifName, new OID("1.3.6.1.2.1.2.2.1.2.7")));
    }

    @Test
    void bridgeTableIsIndexedByMac() {
        OID bridgePort = new OID("1.3.6.1.2.1.17.4.3.1.2");

        assertEquals("00:11:22:33:44:55",
                SnmpScanner.indexKey(bridgePort,
                        new OID("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85")));
    }

    @Test
    void vlanTableKeyCarriesVlanAndMac() {
        OID qFdbPort = new OID("1.3.6.1.2.1.17.7.1.2.2.1.2");

        String key = SnmpScanner.indexKey(qFdbPort,
                new OID("1.3.6.1.2.1.17.7.1.2.2.1.2.20.0.17.34.51.68.85"));

        assertEquals("20:00:11:22:33:44:55", key);
        assertEquals(Integer.valueOf(20), SnmpScanner.vlanOfKey(key));
        assertEquals("00:11:22:33:44:55", SnmpScanner.macOfKey(key));
    }

    @Test
    void vlanNameIsIndexedByVlanOnly() {
        OID vlanName = new OID("1.3.6.1.2.1.17.7.1.4.3.1.1");
        assertEquals("30", SnmpScanner.indexKey(vlanName, new OID("1.3.6.1.2.1.17.7.1.4.3.1.1.30")));
    }

    @Test
    void macPrefixIsNotMistakenForAVlan() {
        // A bare MAC starts with hex that is not numeric, so nothing is stripped.
        assertEquals("aa:bb:cc:dd:ee:ff", SnmpScanner.macOfKey("aa:bb:cc:dd:ee:ff"));
        assertNull(SnmpScanner.vlanOfKey("aa:bb:cc:dd:ee:ff"));
    }

    @Test
    void interfaceDescriptionPrefersTheOperatorAlias() {
        Fake snmp = new Fake().alias("4", "uplink-to-core").name("4", "GigabitEthernet1/0/4");

        assertEquals("uplink-to-core", DiscoveryOrchestrator.describeInterface(snmp.build(), "4"));
    }

    @Test
    void interfaceDescriptionFallsBackToIfName() {
        Fake snmp = new Fake().alias("4", "  ").name("4", "GigabitEthernet1/0/4");

        assertEquals("GigabitEthernet1/0/4", DiscoveryOrchestrator.describeInterface(snmp.build(), "4"));
    }

    @Test
    void interfaceDescriptionIsNullWhenTheDeviceNamesNothing() {
        SnmpScanner.SnmpResult empty = new Fake().build();
        assertNull(DiscoveryOrchestrator.describeInterface(empty, "4"));
        assertNull(DiscoveryOrchestrator.describeInterface(empty, null));
    }

    @Test
    void bridgeTablesPlaceAHostOnItsSwitchPort() throws Exception {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        Device host = device("10.0.0.50", "00:11:22:33:44:55");
        state.byIp.put("10.0.0.50", host);

        Fake snmp = new Fake()
                .name("12", "Gi1/0/12")
                .bridgePort("00:11:22:33:44:55", "12")
                .bridgePortIfIndex("12", "12");

        DiscoveryOrchestrator.applyBridgeTables(state, snmp.build(), device("10.0.0.1", null));

        assertEquals("10.0.0.1", host.metadata.get("l2.switch"));
        assertEquals("12", host.metadata.get("l2.bridgePort"));
        assertEquals("Gi1/0/12", host.metadata.get("l2.portName"));
    }

    @Test
    void vlanTableAttributesTheHostToItsVlan() throws Exception {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        Device host = device("10.0.0.50", "00:11:22:33:44:55");
        state.byIp.put("10.0.0.50", host);

        Fake snmp = new Fake()
                .vlanPort("20:00:11:22:33:44:55", "12")
                .vlanName("20", "SERVERS");

        DiscoveryOrchestrator.applyBridgeTables(state, snmp.build(), device("10.0.0.1", null));

        // The web UI colours by any "vlan." metadata key, so this shape matters.
        assertEquals("12", host.metadata.get("vlan.20"));
        assertEquals("SERVERS", host.metadata.get("vlan.20.name"));
    }

    @Test
    void unknownMacsAreIgnoredRatherThanInvented() throws Exception {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        Fake snmp = new Fake().bridgePort("aa:bb:cc:dd:ee:ff", "12");

        DiscoveryOrchestrator.applyBridgeTables(state, snmp.build(), device("10.0.0.1", null));

        assertTrue(state.byIp.isEmpty(), "a MAC nobody reported must not create a device");
    }

    @Test
    void emptyTablesAreANoOp() throws Exception {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        Device host = device("10.0.0.50", "00:11:22:33:44:55");
        state.byIp.put("10.0.0.50", host);

        DiscoveryOrchestrator.applyBridgeTables(state, new Fake().build(), device("10.0.0.1", null));

        assertTrue(host.metadata.isEmpty());
    }

    private static Device device(String ip, String mac) throws Exception {
        Device device = new Device();
        device.ip = InetAddress.getByName(ip);
        device.mac = mac;
        return device;
    }

    /** Builds an SnmpResult with only the tables a test cares about populated. */
    private static final class Fake {
        private final Map<String,String> aliases = new LinkedHashMap<>();
        private final Map<String,String> names = new LinkedHashMap<>();
        private final Map<String,String> bridgePorts = new LinkedHashMap<>();
        private final Map<String,String> bridgePortIfIndexes = new LinkedHashMap<>();
        private final Map<String,String> vlanPorts = new LinkedHashMap<>();
        private final Map<String,String> vlanNames = new LinkedHashMap<>();

        Fake alias(String index, String value) { aliases.put(index, value); return this; }
        Fake name(String index, String value) { names.put(index, value); return this; }
        Fake bridgePort(String mac, String port) { bridgePorts.put(mac, port); return this; }
        Fake bridgePortIfIndex(String port, String ifIndex) {
            bridgePortIfIndexes.put(port, ifIndex); return this;
        }
        Fake vlanPort(String key, String port) { vlanPorts.put(key, port); return this; }
        Fake vlanName(String vlan, String name) { vlanNames.put(vlan, name); return this; }

        SnmpScanner.SnmpResult build() {
            return new SnmpScanner.SnmpResult("descr", "name", "loc", List.of(),
                    Map.of(), Map.of(), Map.of(), Map.of(), Map.of(),
                    Map.of(), names, aliases,
                    bridgePorts, bridgePortIfIndexes, vlanPorts, vlanNames);
        }
    }
}
