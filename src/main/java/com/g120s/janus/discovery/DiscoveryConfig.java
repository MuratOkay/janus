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
    /** Ranges that must never be probed, even when a seed or route covers them. */
    public final List<String> excludeCidrs = new ArrayList<>();
    public final List<String> snmpCommunities = new ArrayList<>(List.of("public"));
    public final List<Credential> vmCreds = new ArrayList<>();
    public int threadPool = 64;
    public int tcpTimeoutMs = 500;
    public int snmpTimeoutMs = 1_000;
    public int maxSubnets = 64;
    public int maxDepth = 4;
    public int maxHostsPerSubnet = 1024;   // caps probing of very large ranges
    public SweepPolicy sweepPolicy = SweepPolicy.FULL;
    public int sampleHostsPerSubnet = 32;  // SAMPLE policy: addresses picked at random
    public int probesPerSecond;            // 0 = no pacing, only the thread pool limits
    public int lldpDurationMs = 45_000;
    public String outputPath = "discovery-report.json";
    public int dnsTimeoutMs = 800;
    public String dnsServer;          // null = system default
    public boolean tcp = true;
    public boolean icmp = true;
    public boolean arp = true;
    public boolean mdns = true;
    public boolean ssdp = true;
    public boolean netbios = true;
    public boolean snmp = true;
    public boolean lldp = true;
    public boolean dns = true;        // reverse DNS name resolution
    public boolean tlsNames = true;   // TLS certificate CN/SAN name resolution

    public static DiscoveryConfig fromArgs(String[] args) {
        DiscoveryConfig config = new DiscoveryConfig();
        boolean snmpCommunityGiven = false;
        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--cidr" -> config.seedCidrs.add(requireCidr(value(args, ++i, option)));
                case "--exclude" -> config.excludeCidrs.add(requireCidr(value(args, ++i, option)));
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
                case "--dns-timeout" -> config.dnsTimeoutMs = positiveInt(value(args, ++i, option), option);
                case "--dns-server" -> config.dnsServer = nonBlank(value(args, ++i, option), option);
                case "--max-subnets" -> config.maxSubnets = positiveInt(value(args, ++i, option), option);
                case "--max-depth" -> config.maxDepth = positiveInt(value(args, ++i, option), option);
                case "--max-hosts-per-subnet" ->
                        config.maxHostsPerSubnet = positiveInt(value(args, ++i, option), option);
                case "--sweep-policy" ->
                        config.sweepPolicy = SweepPolicy.parse(value(args, ++i, option), option);
                case "--sample-hosts-per-subnet" ->
                        config.sampleHostsPerSubnet = positiveInt(value(args, ++i, option), option);
                case "--pps" -> config.probesPerSecond = positiveInt(value(args, ++i, option), option);
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
                case "--dns" -> config.dns = true;
                case "--no-dns" -> config.dns = false;
                case "--tls-names" -> config.tlsNames = true;
                case "--no-tls-names" -> config.tlsNames = false;
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
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        if (config.seedCidrs.stream().distinct().count() != config.seedCidrs.size()) {
            throw new IllegalArgumentException("--cidr cannot be given more than once for the same network");
        }
        validateCredentials(config.vmCreds);
        return config;
    }

    private static Credential csvCredential(String raw, String kind, int defaultPort, String format) {
        String[] parts = raw.split(",", kind.equals("proxmox") ? 4 : 3);
        int expected = kind.equals("proxmox") ? 4 : 3;
        if (parts.length != expected) {
            throw new IllegalArgumentException("--" + kind + " format: " + format);
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
        throw new IllegalArgumentException("Provide --" + kind + " <host/uri> first (" + option + ")");
    }

    private static void validateCredentials(List<Credential> credentials) {
        for (Credential credential : credentials) {
            if (credential.kind.equals("hyperv") || credential.kind.equals("vcenter")) {
                nonBlank(credential.user, "--" + credential.kind + "-user is required");
                nonBlank(credential.passOrKey, "--" + credential.kind + "-pass is required");
            }
        }
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length || args[index].startsWith("--")) {
            throw new IllegalArgumentException("a value is required for " + option);
        }
        return args[index];
    }

    private static String nonBlank(String value, String option) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(option + " must not be blank");
        return value;
    }

    private static int positiveInt(String value, String option) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed > 0) return parsed;
        } catch (NumberFormatException ignored) {
        }
        throw new IllegalArgumentException(option + " must be a positive integer");
    }

    /** Parses and canonicalizes a CIDR; host bits are dropped so comparisons work. */
    private static String requireCidr(String cidr) {
        String normalized;
        try {
            normalized = Cidr.normalize(cidr);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid IPv4 CIDR: " + cidr, e);
        }
        if (Cidr.prefix(normalized) < Cidr.MIN_PREFIX) {
            throw new IllegalArgumentException("CIDR prefix too small: " + cidr
                    + " (minimum /" + Cidr.MIN_PREFIX + "; scan a narrower range)");
        }
        return normalized;
    }
}
