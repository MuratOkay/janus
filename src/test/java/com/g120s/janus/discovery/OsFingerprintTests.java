package com.g120s.janus.discovery;

import com.g120s.janus.model.Device;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OsFingerprintTests {

    private static Device dev() {
        return new Device();
    }

    @Test
    void windowsFromSysDescr() {
        Device d = dev();
        d.metadata.put("sysDescr", "Microsoft Windows Server 2019 Standard");
        assertEquals(OsFingerprint.WINDOWS, OsFingerprint.guess(d));
    }

    @Test
    void linuxFromSysDescr() {
        Device d = dev();
        d.metadata.put("sysDescr", "Linux debian 6.1.0 x86_64");
        assertEquals(OsFingerprint.LINUX, OsFingerprint.guess(d));
    }

    @Test
    void ciscoIosFromSysDescr() {
        Device d = dev();
        d.metadata.put("sysDescr", "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)");
        assertEquals(OsFingerprint.IOS, OsFingerprint.guess(d));
    }

    @Test
    void esxiFromSysDescr() {
        Device d = dev();
        d.metadata.put("sysDescr", "VMware ESXi 7.0.3 build-19193969");
        assertEquals(OsFingerprint.ESXI, OsFingerprint.guess(d));
    }

    @Test
    void windowsFromRdpPort() {
        Device d = dev();
        d.openPorts.add(3389);
        assertEquals(OsFingerprint.WINDOWS, OsFingerprint.guess(d));
    }

    @Test
    void windowsFromSmbAndRpc() {
        Device d = dev();
        d.openPorts.add(445);
        d.openPorts.add(135);
        assertEquals(OsFingerprint.WINDOWS, OsFingerprint.guess(d));
    }

    @Test
    void linuxFromSshOnly() {
        Device d = dev();
        d.openPorts.add(22);
        assertEquals(OsFingerprint.LINUX, OsFingerprint.guess(d));
    }

    @Test
    void printerFromRawPort() {
        Device d = dev();
        d.openPorts.add(9100);
        assertEquals(OsFingerprint.PRINTER, OsFingerprint.guess(d));
    }

    @Test
    void sysDescrBeatsPorts() {
        Device d = dev();
        d.openPorts.add(3389); // Windows port signature
        d.metadata.put("sysDescr", "Linux server");
        assertEquals(OsFingerprint.LINUX, OsFingerprint.guess(d));
    }

    @Test
    void unknownWhenNoSignal() {
        Device d = dev();
        assertNull(OsFingerprint.guess(d));
    }
}
