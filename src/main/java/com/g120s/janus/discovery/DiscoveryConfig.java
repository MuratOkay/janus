package com.g120s.janus.discovery;

import java.util.*;

public final class DiscoveryConfig {
    public static final class Credential {
        public final String kind;
        public final String host;
        public String user;
        public String passOrKey;
        public String domain = "";
        public int port;
        public boolean useHttps;
        public boolean ignoreCert;

        private Credential(String kind, String host, int port, String user, String passOrKey) {
            this.kind = kind;
            this.host = host;
            this.port = port;
            this.user = user;
            this.passOrKey = passOrKey;
        }
    }

    public final List<String> seedCidrs = new ArrayList<>();
    public final List<String> snmpCommunities = new ArrayList<>(List.of("public"));
    public final List<Credential> vmCreds = new ArrayList<>();
    public int threadPool = 64;
    public int tcpTimeoutMs = 500;
    public int snmpTimeoutMs = 1_000;
    public int maxSubnets = 64;
    public int maxDepth = 4;
    public int lldpDurationMs = 45_000;
    public String outputPath = "discovery-report.json";
    public boolean tcp = true;
    public boolean icmp = true;
    public boolean arp = true;
    public boolean mdns = true;
    public boolean ssdp = true;
    public boolean netbios = true;
    public boolean snmp = true;
    public boolean lldp = true;

    public static DiscoveryConfig fromArgs(String[] args) {
        DiscoveryConfig config = new DiscoveryConfig();
        boolean snmpCommunityGiven = false;
        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--cidr" -> config.seedCidrs.add(requireCidr(value(args, ++i, option)));
                case "--snmp" -> {
                    if (!snmpCommunityGiven) {
                        config.snmpCommunities.clear();
                        snmpCommunityGiven = true;
                    }
                    config.snmpCommunities.add(value(args, ++i, option));
                    config.snmp = true;
                }
                case "--out" -> config.outputPath = value(args, ++i, option);
                case "--threads" -> config.threadPool = positiveInt(value(args, ++i, option), option);
                case "--tcp-timeout" -> config.tcpTimeoutMs = positiveInt(value(args, ++i, option), option);
                case "--snmp-timeout" -> config.snmpTimeoutMs = positiveInt(value(args, ++i, option), option);
                case "--max-subnets" -> config.maxSubnets = positiveInt(value(args, ++i, option), option);
                case "--max-depth" -> config.maxDepth = positiveInt(value(args, ++i, option), option);
                case "--lldp-duration" -> config.lldpDurationMs = positiveInt(value(args, ++i, option), option);
                case "--tcp" -> config.tcp = true;
                case "--no-tcp" -> config.tcp = false;
                case "--icmp" -> config.icmp = true;
                case "--no-icmp" -> config.icmp = false;
                case "--arp" -> config.arp = true;
                case "--no-arp" -> config.arp = false;
                case "--mdns" -> config.mdns = true;
                case "--no-mdns" -> config.mdns = false;
                case "--ssdp" -> config.ssdp = true;
                case "--no-ssdp" -> config.ssdp = false;
                case "--netbios" -> config.netbios = true;
                case "--no-netbios" -> config.netbios = false;
                case "--no-snmp" -> config.snmp = false;
                case "--no-lldp" -> config.lldp = false;
                case "--esxi" -> config.vmCreds.add(csvCredential(
                        value(args, ++i, option), "esxi", 22, "host,user,password"));
                case "--proxmox" -> config.vmCreds.add(csvCredential(
                        value(args, ++i, option), "proxmox", 8006, "host,port,user,password"));
                case "--kvm" -> config.vmCreds.add(csvCredential(
                        value(args, ++i, option), "kvm", 22, "host,user,password"));
                case "--hyperv" -> config.vmCreds.add(new Credential(
                        "hyperv", nonBlank(value(args, ++i, option), option), 0, null, null));
                case "--hyperv-user" -> lastCredential(config, "hyperv", option).user = value(args, ++i, option);
                case "--hyperv-pass" -> lastCredential(config, "hyperv", option).passOrKey = value(args, ++i, option);
                case "--hyperv-domain" -> lastCredential(config, "hyperv", option).domain = value(args, ++i, option);
                case "--hyperv-port" -> lastCredential(config, "hyperv", option).port =
                        positiveInt(value(args, ++i, option), option);
                case "--hyperv-https" -> lastCredential(config, "hyperv", option).useHttps = true;
                case "--vcenter" -> config.vmCreds.add(new Credential(
                        "vcenter", nonBlank(value(args, ++i, option), option), 443, null, null));
                case "--vcenter-user" -> lastCredential(config, "vcenter", option).user = value(args, ++i, option);
                case "--vcenter-pass" -> lastCredential(config, "vcenter", option).passOrKey = value(args, ++i, option);
                case "--vcenter-insecure" -> lastCredential(config, "vcenter", option).ignoreCert = true;
                case "--libvirt" -> config.vmCreds.add(new Credential(
                        "libvirt", nonBlank(value(args, ++i, option), option), 0, null, null));
                case "--libvirt-user" -> lastCredential(config, "libvirt", option).user = value(args, ++i, option);
                case "--libvirt-pass" -> lastCredential(config, "libvirt", option).passOrKey = value(args, ++i, option);
                default -> throw new IllegalArgumentException("Bilinmeyen seçenek: " + option);
            }
        }
        if (config.seedCidrs.stream().distinct().count() != config.seedCidrs.size()) {
            throw new IllegalArgumentException("--cidr aynı ağ için birden fazla kez verilemez");
        }
        validateCredentials(config.vmCreds);
        return config;
    }

    private static Credential csvCredential(String raw, String kind, int defaultPort, String format) {
        String[] parts = raw.split(",", kind.equals("proxmox") ? 4 : 3);
        int expected = kind.equals("proxmox") ? 4 : 3;
        if (parts.length != expected) {
            throw new IllegalArgumentException("--" + kind + " biçimi: " + format);
        }
        int port = kind.equals("proxmox") ? positiveInt(parts[1], "--proxmox port") : defaultPort;
        int userIndex = kind.equals("proxmox") ? 2 : 1;
        Credential credential = new Credential(kind, nonBlank(parts[0], "--" + kind + " host"),
                port, nonBlank(parts[userIndex], "--" + kind + " user"),
                nonBlank(parts[userIndex + 1], "--" + kind + " password"));
        return credential;
    }

    private static Credential lastCredential(DiscoveryConfig config, String kind, String option) {
        for (int i = config.vmCreds.size() - 1; i >= 0; i--) {
            Credential credential = config.vmCreds.get(i);
            if (credential.kind.equals(kind)) return credential;
        }
        throw new IllegalArgumentException("Önce --" + kind + " <host/uri> vermelisiniz (" + option + ")");
    }

    private static void validateCredentials(List<Credential> credentials) {
        for (Credential credential : credentials) {
            if (credential.kind.equals("hyperv") || credential.kind.equals("vcenter")) {
                nonBlank(credential.user, "--" + credential.kind + "-user gerekli");
                nonBlank(credential.passOrKey, "--" + credential.kind + "-pass gerekli");
            }
        }
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length || args[index].startsWith("--")) {
            throw new IllegalArgumentException(option + " için bir değer gerekli");
        }
        return args[index];
    }

    private static String nonBlank(String value, String option) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(option + " boş olamaz");
        return value;
    }

    private static int positiveInt(String value, String option) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed > 0) return parsed;
        } catch (NumberFormatException ignored) {
        }
        throw new IllegalArgumentException(option + " pozitif bir tam sayı olmalı");
    }

    private static String requireCidr(String cidr) {
        String[] parts = cidr.split("/", -1);
        if (parts.length != 2) throw new IllegalArgumentException("Geçersiz CIDR: " + cidr);
        try {
            int prefix = Integer.parseInt(parts[1]);
            String[] octets = parts[0].split("\\.", -1);
            if (prefix < 0 || prefix > 32 || octets.length != 4) {
                throw new IllegalArgumentException("Geçersiz IPv4 CIDR: " + cidr);
            }
            for (String octet : octets) {
                int value = Integer.parseInt(octet);
                if (value < 0 || value > 255) throw new IllegalArgumentException("Geçersiz IPv4 CIDR: " + cidr);
            }
            return cidr;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Geçersiz IPv4 CIDR: " + cidr, e);
        }
    }
}
