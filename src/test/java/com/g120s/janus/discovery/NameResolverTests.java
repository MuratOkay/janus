package com.g120s.janus.discovery;

import com.g120s.janus.model.Device;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NameResolverTests {

    private static Device dev() {
        return new Device();
    }

    @Test
    void recordSetsHostname() {
        Device d = dev();
        NameResolver.record(d, "ptr", "web01.corp.example.com");
        assertEquals("web01.corp.example.com", d.hostname);
        assertEquals("web01.corp.example.com", d.hostnamesBySource.get("ptr"));
        assertTrue(d.aliases.contains("web01.corp.example.com"));
        assertEquals("web01.corp.example.com", d.fqdn);
    }

    @Test
    void ptrBeatsMdns() {
        Device d = dev();
        NameResolver.record(d, "mdns", "printer");
        assertEquals("printer", d.hostname);
        NameResolver.record(d, "ptr", "printer.corp.example.com");
        assertEquals("printer.corp.example.com", d.hostname);
    }

    @Test
    void snmpBeatsTls() {
        Device d = dev();
        NameResolver.record(d, "tls", "secure.example.com");
        NameResolver.record(d, "snmp", "core-sw01");
        assertEquals("core-sw01", d.hostname);
    }

    @Test
    void aliasesAccumulate() {
        Device d = dev();
        NameResolver.record(d, "mdns", "nas");
        NameResolver.record(d, "netbios", "NAS01");
        NameResolver.record(d, "ssdp", "Synology NAS");
        assertEquals(3, d.aliases.size());
        assertEquals(3, d.hostnamesBySource.size());
    }

    @Test
    void blankAndNullIgnored() {
        Device d = dev();
        NameResolver.record(d, "ptr", null);
        NameResolver.record(d, "ptr", "   ");
        NameResolver.record(null, "ptr", "x");
        assertNull(d.hostname);
        assertTrue(d.hostnamesBySource.isEmpty());
    }

    @Test
    void normalizeStripsTrailingDot() {
        assertEquals("host.example.com", NameResolver.normalize("host.example.com."));
        assertEquals("host.example.com", NameResolver.normalize("  host.example.com.  "));
    }

    @Test
    void normalizeRejectsIpLike() {
        assertNull(NameResolver.normalize("192.168.1.5"));
        assertNull(NameResolver.normalize("10.0.0.1"));
    }

    @Test
    void normalizeCollapsesWhitespace() {
        assertEquals("Synology NAS", NameResolver.normalize("  Synology   NAS  "));
    }

    @Test
    void pickBestKeepsBestOnNewLowerPriorityRecord() {
        Device d = dev();
        NameResolver.record(d, "ptr", "db01.corp.example.com");
        NameResolver.record(d, "ssdp", "Generic Device");
        assertEquals("db01.corp.example.com", d.hostname,
                "a new lower-priority record must not overwrite the better name");
    }

    @Test
    void ssdpHeadersFriendlyName() {
        String headers = "HTTP/1.1 200 OK\r\n"
                + "CACHE-CONTROL: max-age=1200\r\n"
                + "SERVER: Linux/3.0 UPnP/1.1 MiniUPnPd/2.1\r\n"
                + "friendlyName: Living Room TV\r\n"
                + "\r\n";
        assertEquals("Living Room TV", NameResolver.fromSsdpHeaders(headers));
    }

    @Test
    void ssdpHeadersServerFallback() {
        String headers = "HTTP/1.1 200 OK\r\nSERVER: Synology/DSM UPnP/1.1\r\n\r\n";
        assertEquals("Synology", NameResolver.fromSsdpHeaders(headers));
    }

    @Test
    void ssdpHeadersEmptyWhenNothing() {
        assertNull(NameResolver.fromSsdpHeaders("HTTP/1.1 200 OK\r\n\r\n"));
        assertNull(NameResolver.fromSsdpHeaders(null));
    }
}
