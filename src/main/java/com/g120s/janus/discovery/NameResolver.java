package com.g120s.janus.discovery;

import com.g120s.janus.model.Device;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves the human-readable name of a device from multiple sources.
 *
 * <p>Each source writes the name it finds into {@link Device#hostnamesBySource}, so when a
 * device has more than one name it is visible which source it came from.
 * {@link #pickBest(Device)} picks the best name from that map according to the priority
 * order and writes it into the {@link Device#hostname} field.
 *
 * <p>Sources and their reliability order (lower = more reliable):
 * <ol>
 *   <li>{@code ptr} — reverse DNS; the most accurate FQDN on corporate networks</li>
 *   <li>{@code snmp} — SNMP sysName</li>
 *   <li>{@code tls} — HTTPS certificate CN/SAN</li>
 *   <li>{@code netbios} — NetBIOS name (Windows)</li>
 *   <li>{@code mdns} — mDNS hostname (.local)</li>
 *   <li>{@code ssdp} — UPnP friendlyName</li>
 * </ol>
 */
public final class NameResolver {

    private static final Map<String, Integer> PRIORITY = Map.of(
            "ptr", 10,
            "snmp", 20,
            "tls", 30,
            "netbios", 40,
            "mdns", 50,
            "ssdp", 60);

    private static final Pattern CN_PATTERN = Pattern.compile("CN=([^,]+)");

    private NameResolver() {}

    // ------------------------------------------------------------------
    // Sources
    // ------------------------------------------------------------------

    /**
     * Reverse DNS (PTR) query. First the JVM resolver (hosts file + system DNS),
     * then a direct PTR query through dnsjava.
     *
     * @param ip        target address
     * @param server    optional DNS server (null = system default)
     * @param timeoutMs time budget per query
     * @return the normalized name, or null
     */
    public static String reverseDns(InetAddress ip, String server, int timeoutMs) {
        try {
            String bySystem = ip.getCanonicalHostName();
            if (isUsable(ip, bySystem)) return normalize(bySystem);
        } catch (Exception ignored) {
            // fall back to dnsjava
        }
        try {
            Name reverseName = ReverseMap.fromAddress(ip);
            SimpleResolver resolver = server == null
                    ? new SimpleResolver()
                    : new SimpleResolver(server);
            resolver.setTimeout(Duration.ofMillis(timeoutMs));

            Lookup lookup = new Lookup(reverseName, Type.PTR);
            lookup.setResolver(resolver);
            lookup.setCache(null);
            Record[] records = lookup.run();
            if (records != null) {
                for (Record record : records) {
                    if (record instanceof PTRRecord ptr) {
                        String name = normalize(ptr.getTarget().toString(true));
                        if (name != null && !name.isBlank()) return name;
                    }
                }
            }
        } catch (Exception ignored) {
            // no name
        }
        return null;
    }

    /** Extracts the CN/SAN from an HTTPS certificate. */
    public static String fromTlsCertificate(InetAddress ip, int port, int timeoutMs) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket();
            try (socket) {
                socket.connect(new InetSocketAddress(ip, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                socket.startHandshake();
                java.security.cert.Certificate[] chain = socket.getSession().getPeerCertificates();
                if (chain.length > 0 && chain[0] instanceof java.security.cert.X509Certificate x509) {
                    String cn = firstDnsName(x509);
                    if (cn != null) return normalize(cn);
                }
            }
        } catch (Exception ignored) {
            // no certificate / not TLS
        }
        return null;
    }

    private static String firstDnsName(java.security.cert.X509Certificate cert) {
        try {
            var san = cert.getSubjectAlternativeNames();
            if (san != null) {
                for (var entry : san) {
                    if (entry.size() >= 2 && Integer.valueOf(2).equals(entry.get(0))) {
                        String value = String.valueOf(entry.get(1));
                        if (value != null && value.contains(".")) return value;
                    }
                }
            }
            Matcher m = CN_PATTERN.matcher(cert.getSubjectX500Principal().getName());
            if (m.find()) return m.group(1);
        } catch (Exception ignored) {
            // no name
        }
        return null;
    }

    /** Extracts friendlyName or the model name from SSDP/UPnP response headers. */
    public static String fromSsdpHeaders(String headers) {
        if (headers == null) return null;
        // Preference order: friendlyName, SERVER, modelName
        String friendly = headerValue(headers, "friendlyname");
        if (friendly != null) return normalize(friendly);
        String server = headerValue(headers, "server");
        if (server != null) return normalize(firstToken(server));
        String model = headerValue(headers, "modelname");
        if (model != null) return normalize(model);
        return null;
    }

    private static String headerValue(String block, String key) {
        for (String line : block.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            if (line.substring(0, colon).trim().equalsIgnoreCase(key)) {
                String value = line.substring(colon + 1).trim();
                if (!value.isEmpty()) return value;
            }
        }
        return null;
    }

    /** The first token of a server string such as "Linux/3.0 UPnP/1.1 MiniUPnPd/2.1". */
    private static String firstToken(String server) {
        String first = server.split("[ /]")[0].trim();
        return first.isEmpty() ? server.trim() : first;
    }

    // ------------------------------------------------------------------
    // Collection and selection
    // ------------------------------------------------------------------

    /**
     * Records the name found by a source on the device, adds it to the alias list and
     * re-picks the best name. Blank/invalid names are ignored.
     */
    public static void record(Device device, String source, String name) {
        if (device == null || source == null) return;
        String cleaned = normalize(name);
        if (cleaned == null || cleaned.isBlank()) return;

        device.hostnamesBySource.put(source, cleaned);
        device.aliases.add(cleaned);
        if (device.fqdn == null && cleaned.contains(".")) device.fqdn = cleaned;
        pickBest(device);
    }

    /**
     * Picks the best name among the recorded sources according to the priority order and
     * writes it into the {@link Device#hostname} field. If there is no name at all the
     * current hostname is kept (it is not reset to null).
     */
    public static void pickBest(Device device) {
        if (device == null) return;

        String bestName = null;
        int bestPriority = Integer.MAX_VALUE;

        for (Map.Entry<String, String> entry : device.hostnamesBySource.entrySet()) {
            int priority = PRIORITY.getOrDefault(entry.getKey(), 100);
            if (priority < bestPriority) {
                bestPriority = priority;
                bestName = entry.getValue();
            }
        }

        if (bestName != null) device.hostname = bestName;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Normalizes a name into a reasonable hostname: trims it, drops the trailing dot and
     * collapses redundant whitespace. Returns null for an empty result.
     */
    public static String normalize(String name) {
        if (name == null) return null;
        String value = name.trim().replaceAll("\\s+", " ");
        while (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.isEmpty()) return null;
        // Reject overly long or purely numeric (IP) names
        if (value.length() > 253) return null;
        if (value.matches("[0-9.]+")) return null;
        return value;
    }

    /** Treats the "names" that are just the address returned by the JVM as unusable. */
    private static boolean isUsable(InetAddress ip, String name) {
        if (name == null || name.isBlank()) return false;
        if (name.equals(ip.getHostAddress())) return false;
        String normalized = normalize(name);
        if (normalized == null || normalized.isBlank()) return false;
        // addresses bounced back as-is, like "192.168.1.5", are useless
        return !normalized.matches("[0-9.]+");
    }
}
