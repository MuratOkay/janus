package com.g120s.janus.discovery;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

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
        List<Integer> observed = new CopyOnWriteArrayList<>();
        try (ProbeExecutor pool = new ProbeExecutor(cap)) {
            List<Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < 40; i++) {
                futures.add(pool.submit(() -> {
                    // Count how many tasks are inside the critical section at once by
                    // parking briefly: with the semaphore honoured this cannot exceed cap.
                    observed.add(concurrencyProbe.incrementAndGet());
                    try {
                        Thread.sleep(2);
                    } finally {
                        concurrencyProbe.decrementAndGet();
                    }
                    return null;
                }));
            }
            for (Future<?> future : futures) future.get();
        } finally {
            concurrencyProbe.set(0);
        }

        assertFalse(observed.isEmpty());
        assertTrue(observed.stream().allMatch(n -> n <= cap),
                "observed concurrency " + observed + " exceeded the cap of " + cap);
    }

    @Test
    void aThrowingTaskStillReleasesItsPermit() throws Exception {
        try (ProbeExecutor pool = new ProbeExecutor(1)) {
            Future<?> failing = pool.submit(() -> {
                throw new IllegalStateException("boom");
            });
            assertThrows(java.util.concurrent.ExecutionException.class, failing::get);

            // With the permit leaked this second task would block forever.
            Future<Integer> next = pool.submit(() -> 42);
            assertEquals(42, next.get());
        }
    }

    @Test
    void capIsAtLeastOneEvenWhenMisconfigured() {
        assertTrue(new ProbeExecutor(0).maxConcurrent() >= 1);
        assertTrue(new ProbeExecutor(-5).maxConcurrent() >= 1);
    }

    private static final java.util.concurrent.atomic.AtomicInteger concurrencyProbe =
            new java.util.concurrent.atomic.AtomicInteger();
}
