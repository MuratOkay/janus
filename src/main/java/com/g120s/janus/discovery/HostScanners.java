package com.g120s.janus.discovery;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public final class HostScanners {

    /** TCP connect probe: ICMP bloklu olsa bile port açıksa canlılık kanıtıdır. */
    public static boolean tcpProbe(InetAddress ip, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (Exception e) { return false; }
    }

    /** Birden fazla porta paralel TCP denemesi; açık portları sıralı döndürür. */
    public static List<Integer> tcpScan(ExecutorService pool, InetAddress ip,
                                        List<Integer> ports, int timeoutMs) throws Exception {
        List<Future<Integer>> fs = new ArrayList<>();
        for (int p : ports) fs.add(pool.submit(() -> tcpProbe(ip, p, timeoutMs) ? p : -1));
        List<Integer> open = new ArrayList<>();
        for (Future<Integer> f : fs) { int p = f.get(); if (p > 0) open.add(p); }
        Collections.sort(open);
        return open;
    }

    /** ICMP echo (Java sürümüne göre ICMP veya TCP yankı olabilir; TCP ile desteklenmeli). */
    public static boolean icmp(InetAddress ip, int timeoutMs) {
        try { return ip.isReachable(timeoutMs); } catch (Exception e) { return false; }
    }
}