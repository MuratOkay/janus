package com.g120s.janus.discovery;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * The probe executor exists to make {@code --threads} mean something. A fixed
 * platform-thread pool was previously fed by a sequential loop, so the real
 * concurrency was one host's worth of ports regardless of the setting.
 */
class ProbeExecutorTests {

    @Test
    void probesRunOnVirtualThreads() throws Exception {
        try (ProbeExecutor pool = new ProbeExecutor(8)) {
            Future<Boolean> result = pool.submit(() -> Thread.currentThread().isVirtual());

            assertTrue(result.get(), "probes must run on virtual threads, not platform threads");
        }
    }

    @Test
    void theCapLimitsProbesInFlight() throws Exception {
        int cap = 4;
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        // Opens only once `cap` probes hold a permit at the same time. Until then every
        // probe parks, so a finishing predecessor cannot free a slot for the next one and
        // the measurement is not a race against how fast tasks complete.
        CountDownLatch allPermitsHeld = new CountDownLatch(cap);
        try (ProbeExecutor pool = new ProbeExecutor(cap)) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 40; i++) {
                futures.add(pool.submit(() -> {
                    int concurrent = inFlight.incrementAndGet();
                    peak.accumulateAndGet(concurrent, Math::max);
                    try {
                        allPermitsHeld.countDown();
                        // Bounded: a leaked or over-issued permit must fail this test,
                        // not hang the build.
                        allPermitsHeld.await(5, TimeUnit.SECONDS);
                        return concurrent;
                    } finally {
                        inFlight.decrementAndGet();
                    }
                }));
            }
            for (Future<Integer> future : futures) {
                future.get(5, TimeUnit.SECONDS);
            }
        }

        // Two-sided on purpose. The upper bound is what protects the network; the lower
        // bound is what makes --threads mean anything. A serialized executor would keep
        // the first assertion green while wasting every thread the user asked for.
        assertTrue(peak.get() <= cap,
                "observed concurrency " + peak.get() + " exceeded the cap of " + cap);
        assertEquals(cap, peak.get(), "the cap was never reached, so --threads would be wasted");
    }

    @Test
    void aThrowingTaskStillReleasesItsPermit() throws Exception {
        try (ProbeExecutor pool = new ProbeExecutor(1)) {
            Future<?> failing = pool.submit(() -> {
                throw new IllegalStateException("boom");
            });
            java.util.concurrent.ExecutionException failure =
                    assertThrows(java.util.concurrent.ExecutionException.class, failing::get);
            assertEquals("boom", failure.getCause().getMessage());

            // With the permit leaked this second task would block forever.
            Future<Integer> next = pool.submit(() -> 42);
            assertEquals(42, next.get());
        }
    }

    @Test
    void capIsAtLeastOneEvenWhenMisconfigured() {
        try (ProbeExecutor zeroCap = new ProbeExecutor(0)) {
            assertTrue(zeroCap.maxConcurrent() >= 1);
        }
        try (ProbeExecutor negativeCap = new ProbeExecutor(-5)) {
            assertTrue(negativeCap.maxConcurrent() >= 1);
        }
    }
}
