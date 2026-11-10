package com.g120s.janus.discovery;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public final class HostScanners {

    /** TCP connect probe: even when ICMP is blocked, an open port proves liveness. */
    public static boolean tcpProbe(InetAddress ip, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (Exception e) { return false; }
    }

    /** Parallel TCP attempts against several ports; returns the open ports in order. */
    public static List<Integer> tcpScan(ExecutorService pool, InetAddress ip,
                                        List<Integer> ports, int timeoutMs) throws Exception {
        return tcpScan(pool, ip, ports, timeoutMs, null);
    }

    /**
     * Parallel TCP attempts, each probe passing through {@code limiter} first when
     * one is supplied.
     */
    public static List<Integer> tcpScan(ExecutorService pool, InetAddress ip, List<Integer> ports,
                                        int timeoutMs, RateLimiter limiter) throws Exception {
        List<Future<Integer>> fs = new ArrayList<>();
        for (int p : ports) fs.add(pool.submit(() -> {
            if (limiter != null) limiter.acquire();
            return tcpProbe(ip, p, timeoutMs) ? p : -1;
        }));
        List<Integer> open = new ArrayList<>();
        for (Future<Integer> f : fs) { int p = f.get(); if (p > 0) open.add(p); }
        Collections.sort(open);
        return open;
    }

    /** ICMP echo (may be ICMP or a TCP echo depending on the Java version; prefer TCP). */
    public static boolean icmp(InetAddress ip, int timeoutMs) {
        return icmp(ip, timeoutMs, null);
    }

    /** ICMP echo, paced by {@code limiter} when one is supplied. */
    public static boolean icmp(InetAddress ip, int timeoutMs, RateLimiter limiter) {
        if (limiter != null) limiter.acquire();
        try { return ip.isReachable(timeoutMs); } catch (Exception e) { return false; }
    }

    /**
     * Probes every host's ports concurrently across all hosts.
     *
     * <p>The previous shape scanned one host at a time, waiting for all its ports
     * before starting the next, so only about one host's worth of probes was ever
     * outstanding and {@code --threads} had almost no effect. Submitting every
     * (host, port) pair instead lets the executor's cap decide the real concurrency.
     *
     * @return open ports per host, in ascending order, hosts with none omitted
     */
    public static Map<InetAddress, List<Integer>> tcpSweep(ProbeExecutor pool, List<InetAddress> hosts,
                                                          List<Integer> ports, int timeoutMs,
                                                          RateLimiter limiter) throws Exception {
        return tcpSweep(pool, hosts, ports, timeoutMs, limiter, null);
    }

    /**
     * As above, reporting how many <em>hosts</em> have been fully probed through
     * {@code onProgress}.
     *
     * <p>The count is incremented inside each probe, when its host's last port
     * finishes. Counting in the collection loop instead would freeze the display at
     * the first incomplete future — submission is what takes the time, and it
     * happens before collection begins.
     */
    public static Map<InetAddress, List<Integer>> tcpSweep(ProbeExecutor pool, List<InetAddress> hosts,
                                                          List<Integer> ports, int timeoutMs,
                                                          RateLimiter limiter,
                                                          java.util.function.IntConsumer onProgress)
            throws Exception {
        Map<InetAddress, List<Integer>> open = new LinkedHashMap<>();
        if (hosts.isEmpty() || ports.isEmpty()) return open;

        // One counter per host: it reaches zero when all of that host's ports are done.
        List<java.util.concurrent.atomic.AtomicInteger> remaining = new ArrayList<>(hosts.size());
        for (int i = 0; i < hosts.size(); i++) {
            remaining.add(new java.util.concurrent.atomic.AtomicInteger(ports.size()));
        }
        java.util.concurrent.atomic.AtomicInteger hostsDone =
                new java.util.concurrent.atomic.AtomicInteger();

        List<Future<OpenPort>> futures = new ArrayList<>(hosts.size() * ports.size());
        for (int hostIndex = 0; hostIndex < hosts.size(); hostIndex++) {
            InetAddress host = hosts.get(hostIndex);
            java.util.concurrent.atomic.AtomicInteger left = remaining.get(hostIndex);
            for (int port : ports) {
                futures.add(pool.submit(() -> {
                    try {
                        if (limiter != null) limiter.acquire();
                        return tcpProbe(host, port, timeoutMs) ? new OpenPort(host, port) : null;
                    } finally {
                        if (left.decrementAndGet() == 0) {
                            if (onProgress != null) onProgress.accept(hostsDone.incrementAndGet());
                        }
                    }
                }));
            }
        }
        for (Future<OpenPort> future : futures) {
            OpenPort found = future.get();
            if (found == null) continue;
            open.computeIfAbsent(found.host(), key -> new ArrayList<>()).add(found.port());
        }
        for (List<Integer> hostPorts : open.values()) Collections.sort(hostPorts);
        return open;
    }

    /** A host and a port where a connection succeeded. */
    public record OpenPort(InetAddress host, int port) { }

    /**
     * Pings every host concurrently and returns those that responded.
     *
     * <p>This used to be a plain loop, so a /22 cost roughly 1022 timeout waits with
     * no output at all — the single largest source of dead air in a scan.
     */
    public static List<InetAddress> icmpSweep(ProbeExecutor pool, List<InetAddress> hosts,
                                              int timeoutMs, RateLimiter limiter) throws Exception {
        return icmpSweep(pool, hosts, timeoutMs, limiter, null);
    }

    /** As above, reporting the running count of completed pings as they happen. */
    public static List<InetAddress> icmpSweep(ProbeExecutor pool, List<InetAddress> hosts,
                                              int timeoutMs, RateLimiter limiter,
                                              java.util.function.IntConsumer onProgress)
            throws Exception {
        java.util.concurrent.atomic.AtomicInteger done = new java.util.concurrent.atomic.AtomicInteger();
        List<Future<InetAddress>> futures = new ArrayList<>(hosts.size());
        for (InetAddress host : hosts) {
            futures.add(pool.submit(() -> {
                try {
                    return icmp(host, timeoutMs, limiter) ? host : null;
                } finally {
                    // Counted here, not in the collection loop: collection begins only
                    // after every task has been submitted, so a counter there would
                    // stay at zero for the entire sweep.
                    if (onProgress != null) onProgress.accept(done.incrementAndGet());
                }
            }));
        }
        List<InetAddress> reachable = new ArrayList<>();
        for (Future<InetAddress> future : futures) {
            InetAddress host = future.get();
            if (host != null) reachable.add(host);
        }
        return reachable;
    }
}