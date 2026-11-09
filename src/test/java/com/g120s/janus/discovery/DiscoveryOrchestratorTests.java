package com.g120s.janus.discovery;

import com.g120s.janus.model.DiscoveryResult;
import com.g120s.janus.model.NetworkSegment;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Large subnets must be capped, never rejected. The previous implementation threw
 * "Network too large" for anything wider than a /22, which aborted the whole scan
 * — including the example shipped in the user guide.
 */
class DiscoveryOrchestratorTests {

    @Test
    void expandCapsWideSubnetInsteadOfThrowing() throws Exception {
        DiscoveryOrchestrator.Expansion expansion = DiscoveryOrchestrator.expand("10.20.0.0/16", 1024);

        assertEquals(1024, expansion.addresses().size());
        assertTrue(expansion.truncated(), "65534 hosts cannot fit in 1024 probes");
        assertEquals(65534, expansion.subnetSize());
        assertEquals("10.20.0.1", expansion.addresses().getFirst().getHostAddress());
    }

    @Test
    void expandKeepsSmallSubnetComplete() throws Exception {
        DiscoveryOrchestrator.Expansion expansion = DiscoveryOrchestrator.expand("192.168.1.0/24", 1024);

        assertEquals(254, expansion.addresses().size());
        assertFalse(expansion.truncated());
        assertEquals("192.168.1.1", expansion.addresses().getFirst().getHostAddress());
        assertEquals("192.168.1.254", expansion.addresses().getLast().getHostAddress());
    }

    @Test
    void expandHonoursConfiguredCap() throws Exception {
        DiscoveryOrchestrator.Expansion expansion = DiscoveryOrchestrator.expand("10.0.0.0/22", 10);

        assertEquals(10, expansion.addresses().size());
        assertTrue(expansion.truncated());
        assertEquals(1022, expansion.subnetSize());
    }

    @Test
    void expandCoversPointToPointStyleRanges() throws Exception {
        assertEquals(2, DiscoveryOrchestrator.expand("10.0.0.0/30", 1024).addresses().size());
        // /31 and /32 have no classic host range and must yield nothing, not an error.
        assertTrue(DiscoveryOrchestrator.expand("10.0.0.0/31", 1024).addresses().isEmpty());
        assertTrue(DiscoveryOrchestrator.expand("10.0.0.1/32", 1024).addresses().isEmpty());
    }

    @Test
    void toCidrUsesTheReportedNetmask() {
        DiscoveryOrchestrator.Learned learned =
                DiscoveryOrchestrator.toCidr("192.168.68.10", "255.255.252.0");

        assertNotNull(learned);
        assertEquals("192.168.68.0/22", learned.cidr());
        assertFalse(learned.maskAssumed(), "the mask came from the device");
    }

    @Test
    void toCidrFallsBackToSlash24AndFlagsIt() {
        DiscoveryOrchestrator.Learned learned = DiscoveryOrchestrator.toCidr("10.1.2.3", null);

        assertNotNull(learned);
        assertEquals("10.1.2.0/24", learned.cidr());
        assertTrue(learned.maskAssumed(), "a guessed prefix must stay visible in the report");
    }

    @Test
    void toCidrIgnoresGarbage() {
        assertNull(DiscoveryOrchestrator.toCidr("not-an-ip", null));
        assertNull(DiscoveryOrchestrator.toCidr(null, "255.255.255.0"));
    }

    @Test
    void unroutableRangesAreSkipped() {
        assertAll(
                () -> assertTrue(DiscoveryOrchestrator.isUnroutable("0.0.0.0/0")),
                () -> assertTrue(DiscoveryOrchestrator.isUnroutable("127.0.0.0/8")),
                () -> assertTrue(DiscoveryOrchestrator.isUnroutable("169.254.1.0/24")),
                () -> assertTrue(DiscoveryOrchestrator.isUnroutable("224.0.0.0/4")),
                () -> assertFalse(DiscoveryOrchestrator.isUnroutable("10.20.0.0/16"))
        );
    }

    @Test
    void hostsInsideASegmentAreRecognised() throws Exception {
        assertTrue(inside("192.168.69.7", "192.168.68.0/22"));
        assertFalse(inside("192.168.72.7", "192.168.68.0/22"));
    }

    /** sameCidr is private; the public behaviour is exercised through Cidr.contains. */
    private static boolean inside(String ip, String cidr) throws Exception {
        return Cidr.contains(cidr, InetAddress.getByName(ip).getHostAddress() + "/32");
    }

    @Test
    void expansionAddressesAreAnImmutableSnapshot() throws Exception {
        List<InetAddress> addresses = DiscoveryOrchestrator.expand("10.0.0.0/29", 1024).addresses();
        assertThrows(UnsupportedOperationException.class, () -> addresses.add(null));
    }

    // -- Phase 2: hierarchy, depth and containment ------------------------

    @Test
    void seedsAreDepthZeroAndChildrenCountHops() {
        DiscoveryOrchestrator orchestrator = offline(new DiscoveryConfig());
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.0.0/24", false),
                "seed", null, null);
        NetworkSegment seed = state.frontier.poll();
        assertNotNull(seed);
        assertEquals(0, seed.depth);
        assertNull(seed.parentCidr);

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.1.0/24", false),
                "snmp-route@10.0.0.1", seed, "10.0.0.1");
        NetworkSegment child = state.frontier.poll();
        assertNotNull(child);
        assertEquals(1, child.depth, "one hop away from the seed");
        assertEquals("10.0.0.0/24", child.parentCidr);
        assertEquals("10.0.0.1", child.gateway);
    }

    @Test
    void depthLimitStopsTheCrawlAndSaysSo() {
        DiscoveryConfig config = new DiscoveryConfig();
        config.maxDepth = 1;
        DiscoveryOrchestrator orchestrator = offline(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        NetworkSegment seed = segment("10.0.0.0/24", 0);
        NetworkSegment depthOne = segment("10.0.1.0/24", 1);

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.1.0/24", false),
                "snmp-route", seed, null);
        assertEquals(1, state.frontier.size(), "depth 1 is still allowed");

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.2.0/24", false),
                "snmp-route", depthOne, null);
        assertEquals(1, state.frontier.size(), "depth 2 exceeds maxDepth");
        assertTrue(state.r.warnings.stream().anyMatch(w -> w.contains("depth limit 1")),
                state.r.warnings.toString());
    }

    @Test
    void duplicateAndOversizedSegmentsAreNotQueuedTwice() {
        DiscoveryConfig config = new DiscoveryConfig();
        config.maxSubnets = 4;
        DiscoveryOrchestrator orchestrator = offline(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        DiscoveryOrchestrator.Learned learned = new DiscoveryOrchestrator.Learned("10.0.0.0/24", false);
        orchestrator.enqueue(state, learned, "seed", null, null);
        orchestrator.enqueue(state, learned, "snmp-route", null, null);
        assertEquals(1, state.frontier.size(), "the same subnet must not be queued twice");

        // Host bits in the candidate must not defeat the duplicate check.
        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.0.99/24", false),
                "snmp-if", null, null);
        assertEquals(1, state.frontier.size());

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("0.0.0.0/0", false),
                "snmp-route", null, null);
        assertEquals(1, state.frontier.size(), "a /0 is not a LAN");
        assertTrue(state.r.warnings.stream().anyMatch(w -> w.contains("oversized")),
                state.r.warnings.toString());
    }

    @Test
    void aFullySweptSupernetSupersedesItsChildren() {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        state.swept.put("192.168.68.0/22", swept("192.168.68.0/22", 1022, 1022));

        NetworkSegment covering = DiscoveryOrchestrator.coveringSegment(state, "192.168.69.0/24");
        assertNotNull(covering, "a /24 inside a completed /22 needs no sweep of its own");
        assertEquals("192.168.68.0/22", covering.cidr);
    }

    @Test
    void aTruncatedSupernetDoesNotSupersedeItsChildren() {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        // Only the first 1024 of 65534 addresses were probed, so the rest is unknown.
        state.swept.put("10.0.0.0/16", swept("10.0.0.0/16", 1024, 65534));

        assertNull(DiscoveryOrchestrator.coveringSegment(state, "10.0.200.0/24"),
                "an incomplete sweep cannot stand in for a narrower network");
    }

    @Test
    void unrelatedNetworksAreNotCovered() {
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
        state.swept.put("192.168.68.0/22", swept("192.168.68.0/22", 1022, 1022));

        assertNull(DiscoveryOrchestrator.coveringSegment(state, "192.168.1.0/24"));
    }

    @Test
    void fullyScannedNeedsActualCoverageNumbers() {
        assertTrue(DiscoveryOrchestrator.fullyScanned(swept("10.0.0.0/24", 254, 254)));
        assertFalse(DiscoveryOrchestrator.fullyScanned(swept("10.0.0.0/24", 100, 254)));
        assertFalse(DiscoveryOrchestrator.fullyScanned(swept("10.0.0.0/24", 0, 0)),
                "a segment no strategy touched is not fully scanned");
    }

    private static DiscoveryOrchestrator offline(DiscoveryConfig config) {
        config.tcp = false;
        config.icmp = false;
        config.arp = false;
        config.mdns = false;
        config.ssdp = false;
        config.netbios = false;
        config.snmp = false;
        config.lldp = false;
        config.dns = false;
        config.tlsNames = false;
        return new DiscoveryOrchestrator(config);
    }

    private static NetworkSegment segment(String cidr, int depth) {
        NetworkSegment segment = new NetworkSegment(cidr);
        segment.depth = depth;
        return segment;
    }

    private static NetworkSegment swept(String cidr, int probed, long total) {
        NetworkSegment segment = new NetworkSegment(cidr);
        segment.hostsProbed = probed;
        segment.hostsTotal = total;
        return segment;
    }
}
