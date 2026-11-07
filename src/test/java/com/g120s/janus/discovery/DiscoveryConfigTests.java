package com.g120s.janus.discovery;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DiscoveryConfigTests {
    @Test
    void parsesRepeatedNetworksCommunitiesAndScannerOptions() {
        DiscoveryConfig config = DiscoveryConfig.fromArgs(new String[] {
                "--cidr", "192.168.1.0/24",
                "--cidr", "10.0.0.0/24",
                "--snmp", "public",
                "--snmp", "private",
                "--threads", "32",
                "--arp",
                "--out", "report.json"
        });

        assertEquals(2, config.seedCidrs.size());
        assertEquals(2, config.snmpCommunities.size());
        assertTrue(config.snmp);
        assertTrue(config.arp);
        assertEquals(32, config.threadPool);
        assertEquals("report.json", config.outputPath);
    }

    @Test
    void parsesVirtualizationCredentials() {
        DiscoveryConfig config = DiscoveryConfig.fromArgs(new String[] {
                "--esxi", "esxi.example,admin,password",
                "--proxmox", "pve.example,8006,root@pam,password",
                "--kvm", "kvm.example,admin,password"
        });

        assertEquals(3, config.vmCreds.size());
        assertEquals("proxmox", config.vmCreds.get(1).kind);
        assertEquals(8006, config.vmCreds.get(1).port);
    }

    @Test
    void parsesHypervisorCredentialsAndTopologyOptions() {
        DiscoveryConfig config = DiscoveryConfig.fromArgs(new String[] {
                "--hyperv", "hv.example",
                "--hyperv-domain", "CORP",
                "--hyperv-user", "scanner",
                "--hyperv-pass", "secret",
                "--vcenter", "https://vc.example/sdk",
                "--vcenter-user", "readonly",
                "--vcenter-pass", "secret",
                "--vcenter-insecure",
                "--libvirt", "qemu+ssh://root@kvm.example/system",
                "--no-lldp",
                "--lldp-duration", "1000"
        });

        assertEquals(3, config.vmCreds.size());
        assertEquals("CORP", config.vmCreds.getFirst().domain);
        assertTrue(config.vmCreds.get(1).ignoreCert);
        assertEquals("libvirt", config.vmCreds.getLast().kind);
        assertFalse(config.lldp);
        assertEquals(1000, config.lldpDurationMs);
    }

    @Test
    void rejectsMalformedNetworksAndMissingOptionValues() {
        assertAll(
                () -> assertThrows(IllegalArgumentException.class,
                        () -> DiscoveryConfig.fromArgs(new String[] {"--cidr", "192.168.1.1"})),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> DiscoveryConfig.fromArgs(new String[] {"--threads", "0"})),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> DiscoveryConfig.fromArgs(new String[] {"--snmp"})),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> DiscoveryConfig.fromArgs(new String[] {"--vcenter", "vc.example"})),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> DiscoveryConfig.fromArgs(new String[] {"--hyperv-user", "scanner"}))
        );
    }
}
