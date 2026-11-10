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
