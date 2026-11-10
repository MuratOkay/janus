package com.g120s.janus.discovery;

import com.g120s.janus.model.DiscoveryResult;
import com.g120s.janus.model.NetworkSegment;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Progress must never be guessed. The total number of segments is unknown while the
 * BFS runs, so the display reports "of >=" rather than inventing a denominator, and
 * the default wiring must stay completely silent.
 */
class ProgressTests {

    @Test
    void defaultWiringEmitsNothingAndNeverThrows() {
        // The no-op implementation is what tests and the web path use.
        assertDoesNotThrow(() -> {
            Progress.NONE.start(new DiscoveryConfig(), List.of("10.0.0.0/24"));
            Progress.NONE.phase("x");
            Progress.NONE.segmentStart(new NetworkSegment("10.0.0.0/24"), 1, 0, 10);
            Progress.NONE.segmentProgress(new NetworkSegment("10.0.0.0/24"), "tcp", 1, 10, 0);
            Progress.NONE.segmentDone(new NetworkSegment("10.0.0.0/24"), 5, 1);
            Progress.NONE.note("x");
        });
    }

    @Test
    void orchestratorWithoutProgressStaysSilent() throws Exception {
        DiscoveryConfig cfg = quietConfig();
        // No Progress argument: the old constructor must remain side-effect free.
        DiscoveryResult result = new DiscoveryOrchestrator(cfg).run();

        assertNotNull(result);
    }

    @Test
    void recordedEventsAreOrderedAndBalanced() throws Exception {
        Recording recording = new Recording();
        new DiscoveryOrchestrator(quietConfig(), recording).run();

        assertEquals(1, recording.starts.get(), "start is announced once");
        assertTrue(recording.phases.get() >= 1, "at least the queueing phase is announced");
        assertEquals(recording.segmentStarts.get(), recording.segmentDones.get(),
                "every started segment must also finish");
        assertTrue(recording.segmentStarts.get() >= 1);
    }

    @Test
    void segmentStartReportsTargetsAndAnHonestLowerBound() throws Exception {
        Recording recording = new Recording();
        DiscoveryConfig cfg = quietConfig();
        cfg.seedCidrs.clear();
        cfg.seedCidrs.add("192.0.2.0/30");
        // Probing must actually be enabled, otherwise no target list is ever built
        // and the count would be trivially zero. TEST-NET-1 is unroutable by
        // definition, so the probes fail immediately instead of touching the network.
        cfg.tcp = true;
        cfg.tcpTimeoutMs = 1;
        cfg.maxHostsPerSubnet = 16;
        new DiscoveryOrchestrator(cfg, recording).run();

        assertEquals(1, recording.segmentStarts.get());
        assertEquals(2, recording.lastTargets, "a /30 holds two usable addresses");
    }

    @Test
    void disabledProbingReportsNoTargetsRatherThanGuessing() throws Exception {
        Recording recording = new Recording();
        // tcp and icmp both off: nothing will be probed, and the display must say so
        // instead of showing a plausible-looking count.
        new DiscoveryOrchestrator(quietConfig(), recording).run();

        assertEquals(1, recording.segmentStarts.get());
        assertEquals(0, recording.lastTargets);
    }

    @Test
    void scanningANetworkThisHostIsNotOnIsReported() throws Exception {
        // The failure this guards against: pointing Janus at a range the machine is
        // not attached to used to yield a long silent scan and "0 devices" with an
        // empty warning list, which reads exactly like a genuinely empty network.
        DiscoveryConfig config = new DiscoveryConfig();
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
        config.seedCidrs.add("203.0.113.0/24");   // TEST-NET-3, never local
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state =
                new DiscoveryOrchestrator.CrawlState(new com.g120s.janus.model.DiscoveryResult());

        state.frontier.add(new NetworkSegment("203.0.113.0/24"));
        orchestrator.warnAboutUnreachableSeeds(state);

        assertTrue(state.r.warnings.stream()
                        .anyMatch(w -> w.contains("not on any local interface")),
                state.r.warnings.toString());
    }

    @Test
    void localSegmentsDoNotTriggerTheWarning() throws Exception {
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(new DiscoveryConfig());
        DiscoveryOrchestrator.CrawlState state =
                new DiscoveryOrchestrator.CrawlState(new com.g120s.janus.model.DiscoveryResult());

        List<String> locals = DiscoveryOrchestrator.localCidrs();
        for (String local : locals) {
            state.frontier.add(new NetworkSegment(local));
        }
        orchestrator.warnAboutUnreachableSeeds(state);

        assertTrue(state.r.warnings.stream().noneMatch(w -> w.contains("not on any local interface")),
                "the host's own networks must never be reported as unreachable");
        for (String local : locals) {
            assertTrue(DiscoveryOrchestrator.isOnLocalSegment(local), local + " should be local");
        }
    }

    @Test
    void emptiedSegmentExplainsItself() throws Exception {
        // Probes run but nothing answers: the report must say so rather than implying
        // the subnet is empty. TEST-NET-1 is unroutable, so this stays offline.
        DiscoveryConfig config = new DiscoveryConfig();
        config.icmp = false;
        config.arp = false;
        config.mdns = false;
        config.ssdp = false;
        config.netbios = false;
        config.snmp = false;
        config.lldp = false;
        config.dns = false;
        config.tlsNames = false;
        config.tcp = true;
        config.tcpTimeoutMs = 1;
        config.maxHostsPerSubnet = 2;
        config.seedCidrs.add("198.51.100.0/30");

        com.g120s.janus.model.DiscoveryResult result = new DiscoveryOrchestrator(config).run();

        assertTrue(result.warnings.stream().anyMatch(w -> w.contains("no host answered any of")),
                result.warnings.toString());
    }

    @Test
    void aSubnetOfTheLocalInterfaceIsStillOnLink() {
        // The bug: ARP required an exact CIDR match, so scanning 192.168.68.0/24 from
        // an interface holding 192.168.68.0/22 skipped ARP for a scannable range.
        assertTrue(DiscoveryOrchestrator.isOnLink("192.168.68.0/22", "192.168.68.0/24"));
        assertTrue(DiscoveryOrchestrator.isOnLink("192.168.68.0/22", "192.168.68.0/22"));
        assertTrue(DiscoveryOrchestrator.isOnLink("192.168.68.5/22", "192.168.68.0/24"),
                "host bits in the interface CIDR must not defeat the match");
    }

    @Test
    void aWiderRangeThanTheInterfaceIsNotOnLink() {
        // A /16 enclosing the interface's /24 spans networks this link cannot ARP.
        assertFalse(DiscoveryOrchestrator.isOnLink("192.168.68.0/24", "192.168.0.0/16"));
        assertFalse(DiscoveryOrchestrator.isOnLink("192.168.68.0/22", "192.168.72.0/24"));
    }

    @Test
    void progressModeIsParsedAndQuietIsAnAliasForNone() {
        assertEquals(ProgressMode.PLAIN,
                DiscoveryConfig.fromArgs(new String[] {"--progress", "plain"}).progress);
        assertEquals(ProgressMode.NONE,
                DiscoveryConfig.fromArgs(new String[] {"--quiet"}).progress);
        assertEquals(ProgressMode.AUTO, DiscoveryConfig.fromArgs(new String[] {}).progress);
        assertThrows(IllegalArgumentException.class,
                () -> DiscoveryConfig.fromArgs(new String[] {"--progress", "loud"}));
    }

    private static DiscoveryConfig quietConfig() {
        DiscoveryConfig cfg = new DiscoveryConfig();
        // Everything that would touch the network is disabled: these tests assert on
        // event bookkeeping, not on discovery results.
        cfg.tcp = false;
        cfg.icmp = false;
        cfg.arp = false;
        cfg.mdns = false;
        cfg.ssdp = false;
        cfg.netbios = false;
        cfg.snmp = false;
        cfg.lldp = false;
        cfg.dns = false;
        cfg.tlsNames = false;
        cfg.seedCidrs.add("192.0.2.0/30");
        return cfg;
    }

    /** Counts the events a scan emits, without touching the console. */
    private static final class Recording implements Progress {
        final AtomicInteger starts = new AtomicInteger();
        final AtomicInteger phases = new AtomicInteger();
        final AtomicInteger segmentStarts = new AtomicInteger();
        final AtomicInteger segmentDones = new AtomicInteger();
        volatile int lastTargets = -1;

        @Override public void start(DiscoveryConfig cfg, List<String> seeds) { starts.incrementAndGet(); }
        @Override public void phase(String name) { phases.incrementAndGet(); }
        @Override public void segmentStart(NetworkSegment segment, int index, int queued, int targets) {
            segmentStarts.incrementAndGet();
            lastTargets = targets;
        }
        @Override public void segmentDone(NetworkSegment segment, long millis, int devices) {
            segmentDones.incrementAndGet();
        }
    }
}
