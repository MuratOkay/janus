package com.g120s.janus.discovery;

import com.g120s.janus.model.DiscoveryResult;
import com.g120s.janus.model.NetworkSegment;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Sweep policy decides what gets probed. Blind-sweeping a /16 costs 65534 connect
 * attempts per probe port; the alternative is asking a router which addresses are
 * actually in use.
 */
class SweepPolicyTests {

    @Test
    void parsesPolicyNamesCaseInsensitively() {
        assertAll(
                () -> assertEquals(SweepPolicy.KNOWN, SweepPolicy.parse("known", "--sweep-policy")),
                () -> assertEquals(SweepPolicy.SAMPLE, SweepPolicy.parse("SAMPLE", "--sweep-policy")),
                () -> assertEquals(SweepPolicy.FULL, SweepPolicy.parse("Full", "--sweep-policy"))
        );
    }

    @Test
    void rejectsUnknownPolicyWithTheValidChoices() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> SweepPolicy.parse("sideways", "--sweep-policy"));
        assertTrue(error.getMessage().contains("known, sample, full"), error.getMessage());
    }

    @Test
    void fullIsTheDefaultPolicy() {
        assertEquals(SweepPolicy.FULL, new DiscoveryConfig().sweepPolicy);
    }

    @Test
    void fullPolicyProbesTheCappedRange() throws Exception {
        DiscoveryConfig config = new DiscoveryConfig();
        config.maxHostsPerSubnet = 16;
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        List<InetAddress> targets = orchestrator.hostsToProbe(state, new NetworkSegment("10.0.0.0/16"));

        assertEquals(16, targets.size(), "a /16 is capped, not rejected");
        assertEquals("10.0.0.1", targets.getFirst().getHostAddress());
        assertTrue(state.r.warnings.stream().anyMatch(w -> w.contains("--max-hosts-per-subnet")));
    }

    @Test
    void knownPolicyProbesOnlyHarvestedAddresses() throws Exception {
        DiscoveryConfig config = new DiscoveryConfig();
        config.sweepPolicy = SweepPolicy.KNOWN;
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        DiscoveryOrchestrator.collectKnown(state, "10.5.0.10");
        DiscoveryOrchestrator.collectKnown(state, "10.5.0.11");
        DiscoveryOrchestrator.collectKnown(state, "10.9.0.1");   // different segment
        DiscoveryOrchestrator.collectKnown(state, "garbage");    // ignored

        List<InetAddress> targets = orchestrator.hostsToProbe(state, new NetworkSegment("10.5.0.0/24"));

        assertEquals(List.of("10.5.0.10", "10.5.0.11"),
                targets.stream().map(InetAddress::getHostAddress).toList(),
                "only addresses inside the segment, in numeric order");
    }

    @Test
    void knownPolicyReportsWhenItHasNothingToProbe() throws Exception {
        DiscoveryConfig config = new DiscoveryConfig();
        config.sweepPolicy = SweepPolicy.KNOWN;
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        List<InetAddress> targets = orchestrator.hostsToProbe(state, new NetworkSegment("10.5.0.0/24"));

        assertTrue(targets.isEmpty());
        // Silence here would look like an empty network; say why instead.
        assertTrue(state.r.warnings.stream().anyMatch(w -> w.contains("no SNMP host data")),
                state.r.warnings.toString());
    }

    @Test
    void samplePolicyMixesKnownHostsGatewayAndASpread() throws Exception {
        DiscoveryConfig config = new DiscoveryConfig();
        config.sweepPolicy = SweepPolicy.SAMPLE;
        config.sampleHostsPerSubnet = 8;
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        DiscoveryOrchestrator.collectKnown(state, "10.5.0.10");
        NetworkSegment seg = new NetworkSegment("10.5.0.0/24");
        seg.gateway = "10.5.0.1";

        List<String> targets = orchestrator.hostsToProbe(state, seg).stream()
                .map(InetAddress::getHostAddress).toList();

        assertTrue(targets.contains("10.5.0.10"), "known hosts are always probed");
        assertTrue(targets.contains("10.5.0.1"), "the gateway is always probed");
        assertTrue(targets.size() > 2, "a sample of the range is added");
        assertTrue(targets.size() <= 1 + 1 + 8, targets.size() + " exceeds known + gateway + sample");
        assertEquals(targets.size(), targets.stream().distinct().count(), "no duplicates");
    }

    @Test
    void sampleIsDeterministicSoScansStayComparable() throws Exception {
        List<String> first = DiscoveryOrchestrator.sampleAddresses("10.0.0.0/16", 10).stream()
                .map(InetAddress::getHostAddress).toList();
        List<String> second = DiscoveryOrchestrator.sampleAddresses("10.0.0.0/16", 10).stream()
                .map(InetAddress::getHostAddress).toList();

        assertEquals(first, second, "the same CIDR must sample the same addresses");
        assertEquals(10, first.size());
        assertEquals(10, first.stream().distinct().count());
    }

    @Test
    void sampleSpansTheWholeRangeNotJustTheStart() throws Exception {
        // A /16 capped to its first 1024 addresses would only ever sample 10.0.0.x.
        List<String> sampled = DiscoveryOrchestrator.sampleAddresses("10.0.0.0/16", 64).stream()
                .map(InetAddress::getHostAddress).toList();

        assertTrue(sampled.stream().anyMatch(ip -> !ip.startsWith("10.0.0.")),
                "sampling must cover the range, got " + sampled);
        assertTrue(sampled.stream().allMatch(ip -> Cidr.contains("10.0.0.0/16", ip + "/32")));
    }

    @Test
    void sampleNeverReturnsNetworkOrBroadcastAddresses() throws Exception {
        List<String> sampled = DiscoveryOrchestrator.sampleAddresses("10.0.0.0/24", 254).stream()
                .map(InetAddress::getHostAddress).toList();

        assertFalse(sampled.contains("10.0.0.0"), ".0 is the network address");
        assertFalse(sampled.contains("10.0.0.255"), ".255 is the broadcast address");
    }

    @Test
    void sampleOfAnImpossibleRangeReturnsNothing() throws Exception {
        assertTrue(DiscoveryOrchestrator.sampleAddresses("10.0.0.0/31", 5).isEmpty());
        assertTrue(DiscoveryOrchestrator.sampleAddresses("10.0.0.1/32", 5).isEmpty());
        assertTrue(DiscoveryOrchestrator.sampleAddresses("10.0.0.0/24", 0).isEmpty());
    }

    @Test
    void rateLimiterIsOptional() {
        assertTrue(new RateLimiter(0).unlimited(), "0 means no pacing");
        assertFalse(new RateLimiter(100).unlimited());
    }

    @Test
    void rateLimiterSpacesProbesOut() {
        RateLimiter limiter = new RateLimiter(50);   // 20 ms apart
        long start = System.nanoTime();
        for (int i = 0; i < 5; i++) limiter.acquire();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        // Four gaps are expected between five probes; allow generous slack for CI.
        assertTrue(elapsedMs >= 40, "five probes at 50/s should take >= 40 ms, took " + elapsedMs);
    }
}
