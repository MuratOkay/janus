package com.g120s.janus;

import com.g120s.janus.configuration.JacksonConfig;
import com.g120s.janus.model.Device;
import com.g120s.janus.model.DiscoveryResult;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Rapor JSON'unun yazılıp geri okunabilmesi kritik: web arayüzü tamamen
 * bu dosyaya dayanıyor. {@link java.net.InetAddress} alanları bir dönem
 * deserileştirilemiyordu ve tüm /api/* uçları 500 dönüyordu.
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
        assertTrue(json.contains("\"192.168.1.10\""), "IP düz metin olarak yazılmalı");

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
    void invalidIpFailsLoudly() {
        String json = """
                {"devices":[{"ip":"bu-bir-ip-degil"}],"segments":[],"vms":[],
                 "vhosts":[],"links":[],"warnings":[],"startedAt":0,"finishedAt":0}
                """;
        assertThrows(Exception.class, () -> mapper.readValue(json, DiscoveryResult.class));
    }
}
