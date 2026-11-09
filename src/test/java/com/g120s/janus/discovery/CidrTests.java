package com.g120s.janus.discovery;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Subnet arithmetic is the backbone of segment discovery: a prefix that is
 * silently rewritten changes which hosts get scanned.
 */
class CidrTests {

    @Test
    void normalizeDropsHostBits() {
        assertEquals("192.168.68.0/22", Cidr.normalize("192.168.68.5/22"));
        assertEquals("192.168.1.0/24", Cidr.normalize("192.168.1.0/24"));
        assertEquals("10.0.0.0/8", Cidr.normalize("10.20.30.40/8"));
        assertEquals("0.0.0.0/0", Cidr.normalize("1.2.3.4/0"));
    }

    @Test
    void normalizeRejectsMalformedValues() {
        assertAll(
                () -> assertThrows(IllegalArgumentException.class, () -> Cidr.normalize("192.168.1.1")),
                () -> assertThrows(IllegalArgumentException.class, () -> Cidr.normalize("192.168.1.1/33")),
                () -> assertThrows(IllegalArgumentException.class, () -> Cidr.normalize("192.168.1.256/24")),
                () -> assertThrows(IllegalArgumentException.class, () -> Cidr.normalize("192.168.1/24")),
                () -> assertThrows(IllegalArgumentException.class, () -> Cidr.normalize(null))
        );
    }

    @Test
    void prefixIsReadBack() {
        assertEquals(22, Cidr.prefix("192.168.68.0/22"));
        assertEquals(32, Cidr.prefix("10.0.0.1/32"));
    }

    @Test
    void maskToPrefixHandlesContiguousMasks() {
        assertEquals(22, Cidr.maskToPrefix("255.255.252.0"));
        assertEquals(24, Cidr.maskToPrefix("255.255.255.0"));
        assertEquals(32, Cidr.maskToPrefix("255.255.255.255"));
        assertEquals(0, Cidr.maskToPrefix("0.0.0.0"));
    }

    @Test
    void maskToPrefixRejectsNonContiguousMasks() {
        assertNull(Cidr.maskToPrefix("255.0.255.0"), "a mask full of holes is not a prefix");
        assertNull(Cidr.maskToPrefix("garbage"));
        assertNull(Cidr.maskToPrefix(null));
    }

    @Test
    void fromMaskKeepsTheRealPrefix() {
        // The bug this guards against: every learned subnet used to become a /24.
        assertEquals("192.168.68.0/22", Cidr.fromMask("192.168.68.10", "255.255.252.0"));
        assertEquals("10.5.0.0/16", Cidr.fromMask("10.5.9.9", "255.255.0.0"));
    }

    @Test
    void fromMaskRejectsUnusableInput() {
        assertNull(Cidr.fromMask("192.168.1.1", "0.0.0.0"), "a /0 is wider than any LAN");
        assertNull(Cidr.fromMask("192.168.1.1", null));
        assertNull(Cidr.fromMask("not-an-ip", "255.255.255.0"));
    }

    @Test
    void containsUnderstandsSupernets() {
        assertTrue(Cidr.contains("192.168.68.0/22", "192.168.69.5/32"));
        assertTrue(Cidr.contains("192.168.68.0/22", "192.168.68.0/24"));
        // 192.168.68.0/22 spans .68 through .71, so .70 is inside and .72 is not.
        assertTrue(Cidr.contains("192.168.68.0/22", "192.168.70.1/32"));
        assertFalse(Cidr.contains("192.168.68.0/22", "192.168.72.1/32"));
        assertFalse(Cidr.contains("192.168.68.0/24", "192.168.68.0/22"),
                "a narrower network cannot contain a wider one");
        assertFalse(Cidr.contains("192.168.68.0/22", "not-a-cidr"));
    }
}
