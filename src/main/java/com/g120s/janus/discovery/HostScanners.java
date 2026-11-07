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
        List<Future<Integer>> fs = new ArrayList<>();
        for (int p : ports) fs.add(pool.submit(() -> tcpProbe(ip, p, timeoutMs) ? p : -1));
        List<Integer> open = new ArrayList<>();
        for (Future<Integer> f : fs) { int p = f.get(); if (p > 0) open.add(p); }
        Collections.sort(open);
        return open;
    }

    /** ICMP echo (may be ICMP or a TCP echo depending on the Java version; prefer TCP). */
    public static boolean icmp(InetAddress ip, int timeoutMs) {
        try { return ip.isReachable(timeoutMs); } catch (Exception e) { return false; }
    }
}