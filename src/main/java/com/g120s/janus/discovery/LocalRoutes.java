package com.g120s.janus.discovery;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the scanner host's own IPv4 routing table so discovery can start from
 * every network this machine can reach, not only the ones it has an interface on.
 * A machine with a static route to a branch office has been told about that
 * network explicitly; ignoring it loses a whole subnet.
 *
 * <p>Only {@code /proc/net/route} is used, so this is a no-op on platforms that
 * do not provide it.
 */
public final class LocalRoutes {

    private static final Path PROC_ROUTE = Path.of("/proc/net/route");
    private static final int RTF_UP = 0x0001;
    private static final int RTF_GATEWAY = 0x0002;

    /** A route the local host knows about. */
    public record Route(String cidr, String gateway) {
    }

    private LocalRoutes() {
    }

    /** The routes of this host; empty when the routing table is unavailable. */
    public static List<Route> read() {
        try {
            return parse(Files.readAllLines(PROC_ROUTE));
        } catch (IOException | RuntimeException e) {
            // No procfs, no permission, unexpected format: seeding falls back to
            // the interface addresses, which is the previous behaviour.
            return List.of();
        }
    }

    /**
     * Parses the content of {@code /proc/net/route}. The default route is skipped
     * (it points outside the LAN) together with anything not flagged {@code UP}.
     */
    static List<Route> parse(List<String> lines) {
        List<Route> routes = new ArrayList<>();
        if (lines == null) return routes;
        for (String line : lines) {
            if (line == null || line.isBlank()) continue;
            String[] fields = line.trim().split("\\s+");
            // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
            if (fields.length < 8) continue;              // header or truncated row
            Long destination = parseHexIp(fields[1]);
            Long mask = parseHexIp(fields[7]);
            Integer flags = parseHex(fields[3]);
            if (destination == null || mask == null || flags == null) continue;
            if ((flags & RTF_UP) == 0) continue;
            if (destination == 0) continue;               // default route
            if (mask == 0) continue;                      // nothing to enumerate
            String cidr = Cidr.fromMask(Cidr.toIp(destination), Cidr.toIp(mask));
            if (cidr == null) continue;
            // A route without the gateway flag is directly connected and has no next
            // hop, so no gateway is recorded rather than a made-up one.
            String gateway = null;
            if ((flags & RTF_GATEWAY) != 0) {
                Long nextHop = parseHexIp(fields[2]);
                if (nextHop != null) gateway = Cidr.toIp(nextHop);
            }
            routes.add(new Route(cidr, gateway));
        }
        return routes;
    }

    /**
     * The next hop of this host's default route, or {@code null} when there is none.
     *
     * <p>The default route is correctly excluded from {@link #parse} because it is not
     * a crawlable LAN, but its next hop is still a useful fact: whatever answers to
     * that address is, by definition, the device forwarding this host's off-link
     * traffic. That makes it the one router we can identify without any credentials.
     */
    public static String defaultGateway() {
        try {
            return defaultGatewayFrom(Files.readAllLines(PROC_ROUTE));
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Extracts the default route's next hop from {@code /proc/net/route} content. */
    static String defaultGatewayFrom(List<String> lines) {
        if (lines == null) return null;
        for (String line : lines) {
            if (line == null || line.isBlank()) continue;
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 8) continue;
            Long destination = parseHexIp(fields[1]);
            Integer flags = parseHex(fields[3]);
            if (destination == null || flags == null) continue;
            if (destination != 0) continue;                  // not the default route
            if ((flags & RTF_UP) == 0) continue;
            if ((flags & RTF_GATEWAY) == 0) continue;        // no next hop to report
            Long nextHop = parseHexIp(fields[2]);
            if (nextHop == null || nextHop == 0L) return null;
            return Cidr.toIp(nextHop);
        }
        return null;
    }

    private static Integer parseHex(String value) {
        try {
            return Integer.parseInt(value, 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** {@code /proc/net/route} stores addresses little-endian in hex. */
    static Long parseHexIp(String value) {
        if (value == null || value.length() != 8) return null;
        Integer raw = parseHex(value);
        if (raw == null) return null;
        return Integer.toUnsignedLong(Integer.reverseBytes(raw));
    }
}
