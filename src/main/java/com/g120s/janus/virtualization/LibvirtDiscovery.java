package com.g120s.janus.virtualization;

import com.g120s.janus.model.VirtualMachine;
import com.g120s.janus.model.VirtualizationHost;
import org.libvirt.Connect;
import org.libvirt.Domain;
import org.libvirt.Network;
import org.w3c.dom.*;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class LibvirtDiscovery {
    public record Options(String uri, String user, String pass) {}

    private LibvirtDiscovery() {}

    public static List<VirtualizationHost> discover(Options options,
                                                    List<VirtualMachine> vmSink) throws Exception {
        Connect connection;
        try {
            connection = new Connect(options.uri(), true);
        } catch (UnsatisfiedLinkError e) {
            throw new IllegalStateException(
                    "libvirt native library is unavailable. Install libvirt development libraries "
                            + "or use --kvm for SSH/virsh discovery.", e);
        }
        try {
            return collect(connection, options, vmSink);
        } finally {
            connection.close();
        }
    }

    private static List<VirtualizationHost> collect(Connect connection, Options options,
                                                    List<VirtualMachine> vmSink) throws Exception {
        String driver = connection.getType();
        String host = extractHost(options.uri());
        VirtualizationHost virtualizationHost = new VirtualizationHost();
        virtualizationHost.type = driverTypeToKind(driver);
        virtualizationHost.source = "api";
        virtualizationHost.ip = host;
        virtualizationHost.id = virtualizationHost.type + ":" + host;
        virtualizationHost.name = host;
        virtualizationHost.version = "libvirt " + connection.getLibVersion();
        virtualizationHost.metadata.put("driver", driver);
        virtualizationHost.metadata.put("uri", options.uri());

        Set<String> networks = new TreeSet<>();
        for (String networkName : nullToEmpty(connection.listNetworks())) {
            Network network = connection.networkLookupByName(networkName);
            if (network == null) continue;
            networks.add(networkName);
            addNetworkSubnets(network.getXMLDesc(0), virtualizationHost);
        }
        if (!networks.isEmpty()) virtualizationHost.metadata.put("networks", String.join(",", networks));

        Map<String, Domain> domains = new LinkedHashMap<>();
        int[] activeIds = connection.listDomains();
        if (activeIds != null) {
            for (int id : activeIds) {
                Domain domain = connection.domainLookupByID(id);
                if (domain != null) domains.put(domain.getUUIDString(), domain);
            }
        }
        String[] inactiveNames = connection.listDefinedDomains();
        if (inactiveNames != null) {
            for (String name : inactiveNames) {
                Domain domain = connection.domainLookupByName(name);
                if (domain != null) domains.putIfAbsent(domain.getUUIDString(), domain);
            }
        }

        for (Domain domain : domains.values()) {
            VirtualMachine vm = new VirtualMachine();
            vm.hostId = virtualizationHost.id;
            vm.name = domain.getName();
            vm.uuid = domain.getUUIDString();
            vm.powerState = domain.isActive() == 1 ? "running" : "shutoff";
            addDomainInterfaces(domain.getXMLDesc(0), vm, virtualizationHost);
            vmSink.add(vm);
        }
        return List.of(virtualizationHost);
    }

    private static void addDomainInterfaces(String xml, VirtualMachine vm,
                                            VirtualizationHost host) throws Exception {
        Document document = parse(xml);
        NodeList interfaces = document.getElementsByTagName("interface");
        for (int index = 0; index < interfaces.getLength(); index++) {
            Element networkInterface = (Element) interfaces.item(index);
            NodeList macElements = networkInterface.getElementsByTagName("mac");
            String mac = null;
            if (macElements.getLength() > 0) {
                String address = ((Element) macElements.item(0)).getAttribute("address");
                if (!address.isBlank()) mac = address.toLowerCase(Locale.ROOT).replace('-', ':');
            }
            if (mac != null) {
                host.vmMacs.add(mac);
                if (vm.mac == null) vm.mac = mac;
            }
            vm.nics.add((mac == null ? "no-mac" : mac) + "@" + interfaceBacking(networkInterface));
        }
    }

    private static String interfaceBacking(Element networkInterface) {
        String type = networkInterface.getAttribute("type");
        NodeList sources = networkInterface.getElementsByTagName("source");
        if (sources.getLength() == 0) return type.isBlank() ? "unknown" : type;
        Element source = (Element) sources.item(0);
        return switch (type) {
            case "network" -> "net:" + source.getAttribute("network");
            case "bridge" -> "br:" + source.getAttribute("bridge");
            case "direct" -> "macvtap:" + source.getAttribute("dev");
            case "user" -> "slirp";
            case "hostdev" -> "hostdev";
            case "vhostuser" -> "vhostuser:" + source.getAttribute("path");
            case "ethernet" -> "eth:" + source.getAttribute("dev");
            default -> type.isBlank() ? "unknown" : type;
        };
    }

    private static void addNetworkSubnets(String xml, VirtualizationHost host) throws Exception {
        Document document = parse(xml);
        NodeList addresses = document.getElementsByTagName("ip");
        for (int index = 0; index < addresses.getLength(); index++) {
            Element address = (Element) addresses.item(index);
            String ip = address.getAttribute("address");
            if (ip.isBlank() || !ip.contains(".")) continue;
            String prefix = address.getAttribute("prefix");
            if (prefix.isBlank()) prefix = maskToPrefix(address.getAttribute("netmask"));
            if (prefix != null) host.managementNets.add(ip + "/" + prefix);
        }
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static String maskToPrefix(String mask) {
        if (mask == null || mask.isBlank()) return null;
        int prefix = 0;
        for (String octet : mask.split("\\.")) {
            int value;
            try {
                value = Integer.parseInt(octet);
            } catch (NumberFormatException e) {
                return null;
            }
            if (value < 0 || value > 255) return null;
            prefix += Integer.bitCount(value);
        }
        return String.valueOf(prefix);
    }

    private static String extractHost(String uri) {
        try {
            String host = URI.create(uri).getHost();
            if (host != null && !host.isBlank()) return host;
        } catch (IllegalArgumentException ignored) {
        }
        return "localhost";
    }

    private static String driverTypeToKind(String driver) {
        if (driver == null) return "libvirt";
        return switch (driver.toUpperCase(Locale.ROOT)) {
            case "QEMU" -> "kvm";
            case "LXC" -> "lxc";
            case "XEN" -> "xen";
            case "BHYVE" -> "bhyve";
            case "VBOX" -> "virtualbox";
            default -> driver.toLowerCase(Locale.ROOT);
        };
    }

    private static String[] nullToEmpty(String[] values) {
        return values == null ? new String[0] : values;
    }
}
