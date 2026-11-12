package com.g120s.janus.virtualization;

import com.g120s.janus.model.Hardware;
import com.g120s.janus.model.VirtualizationHost;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Reads hardware inventory from a server's management controller over Redfish.
 *
 * <p>Redfish is the reason this tier is worth having: it needs no OS agent and no
 * credentials on the host itself, and it keeps answering when the machine is powered
 * off. One HTTPS endpoint exposes model, serial, processor count and total memory,
 * which is exactly the inventory question, for servers from Dell, HPE, Lenovo,
 * Supermicro and most others.
 *
 * <p>Deliberately limited to inventory. Redfish can also power-cycle hardware, and
 * nothing here calls those endpoints — read-only paths only.
 */
public final class RedfishDiscovery {

    /** Endpoint and credentials for one management controller. */
    public record Options(String host, int port, String user, String pass, boolean ignoreCert) {
    }

    private static final ObjectMapper MAP = new ObjectMapper();
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private RedfishDiscovery() {
    }

    /**
     * Builds a host entry with hardware inventory, or {@code null} when the host has
     * no Redfish service.
     */
    public static VirtualizationHost discover(Options options) throws Exception {
        String base = scheme(options) + "://" + options.host() + ":" + options.port();
        HttpClient client = newClient(options.ignoreCert());
        String auth = Base64.getEncoder().encodeToString(
                (options.user() + ":" + options.pass()).getBytes(java.nio.charset.StandardCharsets.UTF_8));

        JsonNode root = get(client, base + "/redfish/v1/", auth);
        if (root == null) return null;

        VirtualizationHost host = new VirtualizationHost();
        host.id = "redfish:" + options.host();
        host.type = "redfish";
        host.source = "api";
        host.ip = options.host();
        host.name = options.host();
        host.metadata.put("redfish", base);

        JsonNode systems = get(client, base + "/redfish/v1/Systems", auth);
        String systemUrl = firstMemberUrl(systems);
        if (systemUrl == null) return host;

        JsonNode system = get(client, absolute(base, systemUrl), auth);
        if (system == null) return host;

        Hardware hardware = fromSystem(system);
        if (!hardware.isEmpty()) host.hardware = hardware;
        host.name = text(system, "Name", options.host());
        host.version = text(system, "BiosVersion", null);

        // Storage is a separate collection; needs the system URL to find it.
        hardware.disks = storage(client, base, auth, system);
        return host;
    }

    /** Maps a Redfish ComputerSystem resource onto the inventory model. */
    static Hardware fromSystem(JsonNode system) {
        Hardware hardware = new Hardware();
        hardware.source = "redfish";
        hardware.model = firstNonBlank(text(system, "Model", null), text(system, "Name", null));
        hardware.serial = text(system, "SerialNumber", null);

        JsonNode processors = system.path("ProcessorSummary");
        int cores = processors.path("CoreCount").asInt(0);
        if (cores > 0) hardware.cpuCores = cores;
        String cpuModel = text(processors, "Model", null);
        if (cpuModel != null) hardware.cpuType = cpuModel;

        long memoryGiB = system.path("MemorySummary").path("TotalSystemMemoryGiB").asLong(0);
        if (memoryGiB > 0) hardware.memTotalBytes = memoryGiB * 1024L * 1024 * 1024;
        return hardware;
    }

    /**
     * Reads simple volumes and their capacity. Failures are swallowed: a BMC that
     * exposes storage differently should not cost us the CPU and memory we already
     * have.
     */
    static List<Hardware.Disk> storage(HttpClient client, String base, String auth, JsonNode system)
            throws Exception {
        List<Hardware.Disk> disks = new ArrayList<>();
        String storageUrl = text(system.path("Storage"), "@odata.id", null);
        if (storageUrl == null) return disks;
        JsonNode collection = get(client, absolute(base, storageUrl), auth);
        if (collection == null) return disks;

        for (JsonNode member : collection.path("Members")) {
            String url = text(member, "@odata.id", null);
            if (url == null) continue;
            JsonNode controller = get(client, absolute(base, url), auth);
            if (controller == null) continue;
            for (JsonNode volumeRef : controller.path("Volumes")) {
                String volumeUrl = text(volumeRef, "@odata.id", null);
                if (volumeUrl == null) continue;
                JsonNode volumes = get(client, absolute(base, volumeUrl), auth);
                if (volumes == null) continue;
                for (JsonNode summary : volumes.path("Members")) {
                    String oneUrl = text(summary, "@odata.id", null);
                    if (oneUrl == null) continue;
                    JsonNode volume = get(client, absolute(base, oneUrl), auth);
                    if (volume == null) continue;
                    Long capacity = volume.path("CapacityBytes").asLong(0);
                    if (capacity == null || capacity <= 0) continue;
                    disks.add(new Hardware.Disk(text(volume, "Name", oneUrl), null, capacity, null));
                }
            }
        }
        return disks;
    }

    // -- HTTP helpers -----------------------------------------------------

    private static HttpClient newClient(boolean ignoreCert) throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(TIMEOUT);
        if (ignoreCert) {
            // BMCs ship self-signed certificates, so verification is impossible unless
            // the operator installed a trusted one. Only enabled on explicit request.
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{TRUST_ALL}, new SecureRandom());
            builder.sslContext(context);
        }
        return builder.build();
    }

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };

    /** GET a Redfish resource as JSON; {@code null} on any non-success status. */
    private static JsonNode get(HttpClient client, String url, String auth) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Basic " + auth)
                .header("Accept", "application/json")
                .timeout(TIMEOUT)
                .GET()
                .build();
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) return null;
        String body = response.body();
        if (body == null || body.isBlank()) return null;
        return MAP.readTree(body);
    }

    private static String scheme(Options options) {
        // Redfish is HTTPS-only in practice; port 443 or the operator's choice.
        return "https";
    }

    /** Resolves a possibly relative {@code @odata.id} against the service root. */
    static String absolute(String base, String url) {
        if (url == null) return null;
        if (url.startsWith("http://") || url.startsWith("https://")) return url;
        return url.startsWith("/") ? base + url : base + "/" + url;
    }

    /** The first {@code Members[].@odata.id} of a collection. */
    static String firstMemberUrl(JsonNode collection) {
        if (collection == null) return null;
        for (JsonNode member : collection.path("Members")) {
            String url = text(member, "@odata.id", null);
            if (url != null) return url;
        }
        return null;
    }

    private static String text(JsonNode node, String field, String fallback) {
        if (node == null) return fallback;
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return fallback;
        String text = value.asString();
        return text == null || text.isBlank() ? fallback : text;
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }
}
