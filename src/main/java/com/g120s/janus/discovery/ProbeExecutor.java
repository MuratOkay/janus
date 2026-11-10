package com.g120s.janus.discovery;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

/**
 * Runs probes on virtual threads, with a hard cap on how many are in flight.
 *
 * <p>Probing is almost entirely blocking socket I/O, which is exactly what virtual
 * threads are for: a blocked virtual thread costs a small heap object rather than a
 * megabyte of stack, so the previous fixed platform-thread pool was leaving most of
 * {@code --threads} unusable — a sequential outer loop meant only one host's ports
 * were ever outstanding.
 *
 * <p>The cap is applied with a semaphore acquired <em>before</em> submission rather
 * than inside the task. Unbounded submission would create a virtual thread per
 * (host, port) pair, which on a /16 is over a million parked threads; acquiring
 * first keeps only the working set alive. The cap also protects the network and the
 * local ephemeral port range, which virtual threads do not make any larger.
 */
public final class ProbeExecutor implements AutoCloseable {

    private final ExecutorService pool;
    private final Semaphore permits;
    private final int maxConcurrent;

    /** @param maxConcurrent upper bound on probes running or queued at once */
    public ProbeExecutor(int maxConcurrent) {
        this.maxConcurrent = Math.max(1, maxConcurrent);
        this.pool = Executors.newVirtualThreadPerTaskExecutor();
        this.permits = new Semaphore(this.maxConcurrent);
    }

    /** The configured upper bound on concurrent probes. */
    public int maxConcurrent() {
        return maxConcurrent;
    }

    /**
     * Runs {@code task} on a virtual thread, blocking until a slot is free. The
     * permit is released even if the task throws or is cancelled.
     */
    public <T> Future<T> submit(Callable<T> task) {
        permits.acquireUninterruptibly();
        try {
            return pool.submit(() -> {
                try {
                    return task.call();
                } finally {
                    permits.release();
                }
            });
        } catch (RuntimeException | Error e) {
            // Submission failed, so no task will ever release this permit.
            permits.release();
            throw e;
        }
    }

    /** Stops accepting work; already-submitted tasks still complete. */
    public void shutdown() {
        pool.shutdown();
    }

    /** Shuts down and waits for outstanding probes to finish. */
    @Override
    public void close() {
        pool.close();
    }
}
