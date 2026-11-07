package com.g120s.janus.virtualization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.g120s.janus.model.VirtualMachine;
import com.g120s.janus.model.VirtualizationHost;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

public final class ProxmoxDiscovery {
    private static final ObjectMapper MAP = new ObjectMapper();

    public static VirtualizationHost discover(String ip, int port, String user, String pass,
                                               List<VirtualMachine> sink) throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String base = "https://" + ip + ":" + (port == 0 ? 8006 : port) + "/api2/json";
        HttpResponse<String> login = http.send(
                HttpRequest.newBuilder(URI.create(base + "/access/ticket"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "username=" + enc(user) + "&password=" + enc(pass)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        if (login.statusCode() / 100 != 2) {
            throw new IllegalStateException("Proxmox authentication failed: HTTP " + login.statusCode());
        }

        JsonNode loginData = MAP.readTree(login.body()).path("data");
        JsonNode ticketNode = loginData.path("ticket");
        JsonNode csrfNode = loginData.path("CSRFPreventionToken");
        if (ticketNode.isMissingNode() || csrfNode.isMissingNode()) {
            throw new IllegalStateException("Proxmox authentication response is missing its ticket or CSRF token");
        }
        String ticket = ticketNode.asText();
        String csrf = csrfNode.asText();

        VirtualizationHost host = new VirtualizationHost();
        host.ip = ip;
        host.type = "proxmox";
        host.id = "proxmox:" + ip;
        host.name = ip;

        JsonNode nodes = get(http, base + "/nodes", ticket, csrf).path("data");
        for (JsonNode nodeInfo : nodes) {
            String node = nodeInfo.path("node").asText();
            JsonNode vms = get(http, base + "/nodes/" + node + "/qemu", ticket, csrf).path("data");
            for (JsonNode vmInfo : vms) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = vmInfo.path("name").asText();
                vm.hostId = host.id;
                vm.powerState = vmInfo.has("status") ? vmInfo.path("status").asText() : null;
                int vmid = vmInfo.path("vmid").asInt();
                JsonNode config = get(http, base + "/nodes/" + node + "/qemu/" + vmid + "/config",
                        ticket, csrf).path("data");
                for (Iterator<String> fields = config.fieldNames(); fields.hasNext();) {
                    String field = fields.next();
                    if (field.startsWith("net")) {
                        String nic = config.path(field).asText();
                        String mac = regexMac(nic);
                        if (mac != null) {
                            if (vm.mac == null) vm.mac = mac;
                            host.vmMacs.add(mac);
                        }
                        vm.nics.add(nic);
                    }
                }
                sink.add(vm);
            }

            JsonNode containers = get(http, base + "/nodes/" + node + "/lxc", ticket, csrf).path("data");
            for (JsonNode container : containers) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = container.path("name").asText();
                vm.hostId = host.id;
                vm.powerState = container.has("status") ? container.path("status").asText() : null;
                vm.guestOs = "lxc";
                sink.add(vm);
            }

            JsonNode networks = get(http, base + "/nodes/" + node + "/network", ticket, csrf).path("data");
            for (JsonNode network : networks) {
                if (network.hasNonNull("address") && network.hasNonNull("cidr")) {
                    host.managementNets.add(network.path("address").asText()
                            + "/" + network.path("cidr").asText());
                }
            }
        }
        return host;
    }

    private static String regexMac(String value) {
        var matcher = java.util.regex.Pattern
                .compile("(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})").matcher(value);
        return matcher.find() ? matcher.group(1).toLowerCase() : null;
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static JsonNode get(HttpClient client, String url, String ticket, String csrf) throws Exception {
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Cookie", "PVEAuthCookie=" + ticket)
                        .header("CSRFPreventionToken", csrf)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("Proxmox API request failed: HTTP " + response.statusCode());
        }
        return MAP.readTree(response.body());
    }
}
