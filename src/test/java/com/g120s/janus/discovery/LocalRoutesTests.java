package com.g120s.janus.discovery;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The scanner host's own routing table is a source of subnets that no interface
 * enumeration reports: static routes to other LAN segments.
 */
class LocalRoutesTests {

    // Verbatim shape of /proc/net/route. Addresses are little-endian hex, so
    // 192.168.68.0 is "0044A8C0" and its /22 mask is "00FCFFFF".
    private static final List<String> SAMPLE = List.of(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
            "wlo1\t00000000\t0144A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0",
            "wlo1\t0044A8C0\t00000000\t0001\t0\t0\t600\t00FCFFFF\t0\t0\t0",
            "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
            "eth0\t0000010A\t0144A8C0\t0003\t0\t0\t100\t00FFFFFF\t0\t0\t0",
            "eth0\t0000020A\t00000000\t0002\t0\t0\t100\t00FFFFFF\t0\t0\t0"
    );

    @Test
    void decodesLittleEndianAddresses() {
        assertEquals(0xC0A84400L, LocalRoutes.parseHexIp("0044A8C0"));
        assertEquals(0xC0A84401L, LocalRoutes.parseHexIp("0144A8C0"));
        assertEquals(0L, LocalRoutes.parseHexIp("00000000"));
        assertNull(LocalRoutes.parseHexIp("XYZ"));
        assertNull(LocalRoutes.parseHexIp("0044A8"));
    }

    @Test
    void parsesConnectedRouteWithRealPrefix() {
        List<LocalRoutes.Route> routes = LocalRoutes.parse(SAMPLE);

        LocalRoutes.Route local = routes.stream()
                .filter(r -> r.cidr().equals("192.168.68.0/22")).findFirst().orElseThrow();
        // Directly connected routes have no next hop, so no gateway is invented.
        assertNull(local.gateway());
    }

    @Test
    void keepsEveryConnectedNetworkIncludingBridges() {
        List<String> connected = LocalRoutes.parse(SAMPLE).stream()
                .filter(r -> r.gateway() == null)
                .map(LocalRoutes.Route::cidr)
                .toList();

        assertTrue(connected.contains("192.168.68.0/22"), connected.toString());
        assertTrue(connected.contains("172.17.0.0/16"), "the docker bridge is a real subnet");
    }

    @Test
    void parsesRoutedNetworkWithGateway() {
        List<LocalRoutes.Route> routes = LocalRoutes.parse(SAMPLE);

        LocalRoutes.Route routed = routes.stream()
                .filter(r -> r.cidr().equals("10.1.0.0/24")).findFirst().orElseThrow();
        assertEquals("192.168.68.1", routed.gateway());
    }

    @Test
    void skipsDefaultRouteAndDownInterfaces() {
        List<LocalRoutes.Route> routes = LocalRoutes.parse(SAMPLE);

        assertTrue(routes.stream().noneMatch(r -> r.cidr().startsWith("0.0.0.0")),
                "the default route points outside the LAN");
        assertTrue(routes.stream().noneMatch(r -> r.cidr().equals("10.2.0.0/24")),
                "a route without RTF_UP is not usable");
    }

    @Test
    void toleratesHeaderAndTruncatedRows() {
        assertAll(
                () -> assertTrue(LocalRoutes.parse(List.of(
                        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT")).isEmpty()),
                () -> assertTrue(LocalRoutes.parse(List.of("wlo1 0068A8C0")).isEmpty()),
                () -> assertTrue(LocalRoutes.parse(List.of()).isEmpty()),
                () -> assertTrue(LocalRoutes.parse(null).isEmpty())
        );
    }

    @Test
    void readsTheRealTableWithoutThrowing() {
        // Must never fail, whatever platform this runs on.
        assertNotNull(LocalRoutes.read());
    }
}
