package com.g120s.janus;

import com.g120s.janus.configuration.JacksonConfig;
import com.g120s.janus.model.Device;
import com.g120s.janus.model.DiscoveryResult;
import com.g120s.janus.model.Hardware;
import com.g120s.janus.model.NetworkSegment;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Being able to write the report JSON and read it back is critical: the web interface
 * relies on this file entirely. {@link java.net.InetAddress} fields used to be
 * non-deserializable and every /api/* endpoint returned 500.
 */
class ReportJsonRoundTripTests {

    private final JsonMapper mapper = JacksonConfig.cliMapper();

    @Test
    void deviceIpSurvivesRoundTrip() throws Exception {
        DiscoveryResult original = new DiscoveryResult();
        Device device = new Device();
        device.ip = InetAddress.getByName("192.168.1.10");
        device.mac = "00:0c:29:aa:bb:cc";
        device.hostname = "esx-01";
        device.openPorts.add(443);
        original.devices.add(device);

        String json = mapper.writeValueAsString(original);
        assertTrue(json.contains("\"192.168.1.10\""), "the IP must be written as plain text");

        DiscoveryResult decoded = mapper.readValue(json, DiscoveryResult.class);
        assertEquals(1, decoded.devices.size());
        assertEquals("192.168.1.10", decoded.devices.getFirst().ip.getHostAddress());
        assertEquals("00:0c:29:aa:bb:cc", decoded.devices.getFirst().mac);
    }

    @Test
    void nullIpIsTolerated() {
        DiscoveryResult result = new DiscoveryResult();
        Device device = new Device();
        device.mac = "52:54:00:11:22:33";
        result.devices.add(device);

        DiscoveryResult decoded = mapper.readValue(mapper.writeValueAsString(result), DiscoveryResult.class);
        assertNull(decoded.devices.getFirst().ip);
    }

    @Test
    void segmentHierarchySurvivesRoundTrip() throws Exception {
        DiscoveryResult original = new DiscoveryResult();
        NetworkSegment segment = new NetworkSegment("10.0.5.0/24");
        segment.parentCidr = "10.0.0.0/16";
        segment.depth = 2;
        segment.gateway = "10.0.0.1";
        segment.coveredBy = "10.0.0.0/16";
        segment.hostsProbed = 254;
        segment.hostsTotal = 254;
        segment.discoveredBy.add("snmp-if@10.0.0.1");
        original.segments.add(segment);

        DiscoveryResult decoded = mapper.readValue(mapper.writeValueAsString(original), DiscoveryResult.class);
        NetworkSegment read = decoded.segments.getFirst();
        assertEquals("10.0.5.0/24", read.cidr);
        assertEquals("10.0.0.0/16", read.parentCidr);
        assertEquals(2, read.depth);
        assertEquals("10.0.0.1", read.gateway);
        assertEquals("10.0.0.0/16", read.coveredBy);
        assertEquals(254, read.hostsProbed);
        assertEquals(254, read.hostsTotal);
        assertEquals(java.util.Set.of("snmp-if@10.0.0.1"), read.discoveredBy);
    }

    @Test
    void hardwareInventorySurvivesRoundTrip() throws Exception {
        DiscoveryResult original = new DiscoveryResult();
        Device device = new Device();
        device.ip = InetAddress.getByName("192.168.1.10");
        Hardware hardware = new Hardware();
        hardware.cpuCores = 8;
        hardware.cpuType = "Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz";
        hardware.memTotalBytes = 8159805440L;
        hardware.source = "snmp-hr";
        hardware.model = "PowerEdge R640";
        hardware.serial = "ABC1234";
        hardware.disks.add(new Hardware.Disk("/", "ext4", 249792131072L, 98348396544L));
        device.hardware = hardware;
        original.devices.add(device);

        DiscoveryResult decoded = mapper.readValue(mapper.writeValueAsString(original), DiscoveryResult.class);
        Hardware read = decoded.devices.getFirst().hardware;
        assertNotNull(read);
        assertEquals(8, read.cpuCores);
        assertEquals("Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz", read.cpuType);
        assertEquals(8159805440L, read.memTotalBytes);
        assertEquals("snmp-hr", read.source);
        assertEquals("PowerEdge R640", read.model);
        assertEquals("ABC1234", read.serial);
        assertEquals(1, read.disks.size());
        assertEquals("/", read.disks.getFirst().mount());
        assertEquals(249792131072L, read.disks.getFirst().totalBytes());
        assertEquals(98348396544L, read.disks.getFirst().freeBytes());
    }

    @Test
    void devicesWithoutHardwareRoundTripAsNull() throws Exception {
        // Most devices expose nothing; the field must stay absent rather than becoming
        // an object full of zeroes.
        DiscoveryResult original = new DiscoveryResult();
        Device device = new Device();
        device.ip = InetAddress.getByName("192.168.1.1");
        original.devices.add(device);

        DiscoveryResult decoded = mapper.readValue(mapper.writeValueAsString(original), DiscoveryResult.class);

        assertNull(decoded.devices.getFirst().hardware);
    }

    @Test
    void invalidIpFailsLoudly() {
        String json = """
                {"devices":[{"ip":"this-is-not-an-ip"}],"segments":[],"vms":[],
                 "vhosts":[],"links":[],"warnings":[],"startedAt":0,"finishedAt":0}
                """;
        assertThrows(Exception.class, () -> mapper.readValue(json, DiscoveryResult.class));
    }
}
