package com.g120s.janus.discovery;

import java.util.concurrent.TimeUnit;

/**
 * Spaces out probes so a scan cannot flood a network device.
 *
 * <p>The thread pool bounds how many probes are in flight; this bounds how many
 * start per second. The two are different limits: 256 threads still hammer a core
 * switch if every connect returns instantly. A limiter is only installed when the
 * operator asks for one, so the default path pays nothing.
 */
public final class RateLimiter {

    private final long intervalNanos;
    private final Object lock = new Object();
    private long nextFree;

    /** @param permitsPerSecond maximum probe starts per second; {@code <= 0} disables pacing */
    public RateLimiter(int permitsPerSecond) {
        this.intervalNanos = permitsPerSecond <= 0 ? 0 : 1_000_000_000L / permitsPerSecond;
    }

    public boolean unlimited() {
        return intervalNanos == 0;
    }

    /**
     * Reserves the next probe slot, sleeping if it is still in the future. The
     * slot is claimed under the lock and the wait happens outside it, so threads
     * queue in order without blocking each other's reservation.
     */
    public void acquire() {
        if (unlimited()) return;
        long slot;
        synchronized (lock) {
            long now = System.nanoTime();
            if (nextFree < now) nextFree = now;
            slot = nextFree;
            nextFree += intervalNanos;
        }
        long wait = slot - System.nanoTime();
        if (wait <= 0) return;
        try {
            TimeUnit.NANOSECONDS.sleep(wait);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
