package com.g120s.janus.virtualization;

import com.g120s.janus.model.Device;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Fingerprint tespiti MAC OUI'ye dayanıyor. {@code vendorOUI} bir dönem
 * sabit {@code ""} döndürdüğü için Xen/Hyper-V hiç tespit edilemiyordu.
 */
class VirtualizationDetectorTests {

    @Test
    void resolvesVendorFromOui() {
        Device vmware = device("00:0c:29:11:22:33");
        assertEquals("vmware", VirtualizationDetector.vendorOUI(vmware));

        Device xen = device("00:16:3e:aa:bb:cc");
        assertEquals("xen", VirtualizationDetector.vendorOUI(xen));

        Device ms = device("00:15:5D:aa:bb:cc");
        assertEquals("microsoft", VirtualizationDetector.vendorOUI(ms), "büyük harf MAC de çalışmalı");
    }

    @Test
    void unknownOuiYieldsEmptyString() {
        assertEquals("", VirtualizationDetector.vendorOUI(device("de:ad:be:ef:00:01")));
        assertEquals("", VirtualizationDetector.vendorOUI(device(null)));
        assertEquals("", VirtualizationDetector.vendorOUI(device("kisa")));
    }

    @Test
    void winRmPortAloneIsNotEnoughForHyperV() {
        Device workstation = device("00:1b:21:aa:bb:cc");   // Intel NIC
        workstation.openPorts.add(5985);
        assertNull(VirtualizationDetector.guessType(workstation),
                "WinRM açık iş istasyonu Hyper-V host sayılmamalı");

        Device server = device("00:15:5d:aa:bb:cc");        // Hyper-V OUI
        server.openPorts.add(5985);
        assertEquals("hyperv", VirtualizationDetector.guessType(server));
    }

    @Test
    void xenDetectedByOuiOnHttps() {
        Device xen = device("00:16:3e:aa:bb:cc");
        xen.openPorts.add(443);
        assertEquals("xen", VirtualizationDetector.guessType(xen));
    }

    @Test
    void portFingerprintsStillWork() {
        Device esxi = device(null);
        esxi.openPorts.add(902);
        assertEquals("esxi", VirtualizationDetector.guessType(esxi));

        Device proxmox = device(null);
        proxmox.openPorts.add(8006);
        assertEquals("proxmox", VirtualizationDetector.guessType(proxmox));

        Device kvm = device(null);
        kvm.openPorts.add(16509);
        assertEquals("kvm", VirtualizationDetector.guessType(kvm));
    }

    @Test
    void detectsVmMacRanges() {
        assertEquals("vmware", VirtualizationDetector.vmVendorByMac("00:50:56:aa:bb:cc"));
        assertEquals("hyperv", VirtualizationDetector.vmVendorByMac("00:15:5d:aa:bb:cc"));
        assertEquals("qemu-kvm", VirtualizationDetector.vmVendorByMac("52-54-00-aa-bb-cc"));
        assertNull(VirtualizationDetector.vmVendorByMac(null));
        assertNull(VirtualizationDetector.vmVendorByMac("00:11:22:33:44:55"));
    }

    private static Device device(String mac) {
        Device d = new Device();
        d.mac = mac;
        return d;
    }
}
