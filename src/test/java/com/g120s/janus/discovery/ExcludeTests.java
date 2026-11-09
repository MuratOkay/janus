package com.g120s.janus.discovery;

import com.g120s.janus.model.DiscoveryResult;
import com.g120s.janus.model.NetworkSegment;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@code --exclude} is a safety guardrail, not a convenience filter: an operator who
 * excludes a range must not have it probed because a seed or SNMP route happens to
 * enclose it. Every path that could reach an address is checked.
 */
class ExcludeTests {

    @Test
    void excludedSegmentsAreNotQueued() {
        DiscoveryConfig config = new DiscoveryConfig();
        config.excludeCidrs.add("10.0.5.0/24");
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.5.0/24", false),
                "snmp-if@10.0.0.1", null, null);

        assertTrue(state.frontier.isEmpty());
        assertTrue(state.r.warnings.stream().anyMatch(w -> w.contains("excluded 10.0.5.0/24")),
                state.r.warnings.toString());
    }

    @Test
    void anExcludedSubnetInsideAPermittedSeedIsStillQueuedAsASegment() {
        // The /16 itself is allowed; only the /24 inside it is excluded.
        DiscoveryConfig config = new DiscoveryConfig();
        config.excludeCidrs.add("10.0.5.0/24");
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());

        orchestrator.enqueue(state, new DiscoveryOrchestrator.Learned("10.0.0.0/16", false),
                "seed", null, null);

        assertEquals(1, state.frontier.size(), "the wider permitted range is still crawled");
    }

    @Test
    void addressesInsideAnExcludedRangeAreNeverProbed() throws Exception {
        // This is the case that matters: the seed is a supernet of the exclusion, so
        // the segment is legitimate but part of its address space is off limits.
        DiscoveryConfig config = new DiscoveryConfig();
        config.excludeCidrs.add("10.0.5.0/24");
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);

        List<String> targets = orchestrator.withoutExcluded(List.of(
                        InetAddress.getByName("10.0.4.1"),
                        InetAddress.getByName("10.0.5.1"),
                        InetAddress.getByName("10.0.5.254"),
                        InetAddress.getByName("10.0.6.1")))
                .stream().map(InetAddress::getHostAddress).toList();

        assertEquals(List.of("10.0.4.1", "10.0.6.1"), targets);
    }

    @Test
    void filteringIsSkippedEntirelyWithNoExclusions() {
        DiscoveryConfig config = new DiscoveryConfig();
        DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
        List<InetAddress> targets = List.of();

        assertSame(targets, orchestrator.withoutExcluded(targets),
                "the default path must not copy or filter");
    }

    @Test
    void allSweepPoliciesRespectExclusions() throws Exception {
        for (SweepPolicy policy : SweepPolicy.values()) {
            DiscoveryConfig config = new DiscoveryConfig();
            config.excludeCidrs.add("10.0.5.0/24");
            config.maxHostsPerSubnet = 4096;
            config.sweepPolicy = policy;
            DiscoveryOrchestrator orchestrator = new DiscoveryOrchestrator(config);
            DiscoveryOrchestrator.CrawlState state = new DiscoveryOrchestrator.CrawlState(new DiscoveryResult());
            DiscoveryOrchestrator.collectKnown(state, "10.0.5.10");

            NetworkSegment seg = new NetworkSegment("10.0.5.0/24");
            seg.gateway = "10.0.5.1";

            List<String> targets = orchestrator.hostsToProbe(state, seg).stream()
                    .map(InetAddress::getHostAddress).toList();

            assertTrue(targets.isEmpty(),
                    policy + " must not probe an excluded segment, got " + targets);
        }
    }

    @Test
    void exclusionIsParsedAndNormalized() {
        DiscoveryConfig config = DiscoveryConfig.fromArgs(new String[] {
                "--cidr", "10.0.0.0/16",
                "--exclude", "10.0.5.7/24",
                "--exclude", "172.16.0.0/12"
        });

        assertEquals(List.of("10.0.5.0/24", "172.16.0.0/12"), config.excludeCidrs);
    }

    @Test
    void excludesDefaultToNone() {
        assertTrue(DiscoveryConfig.fromArgs(new String[] {}).excludeCidrs.isEmpty());
    }
}
