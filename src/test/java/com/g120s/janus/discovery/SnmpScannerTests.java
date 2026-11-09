package com.g120s.janus.discovery;

import org.junit.jupiter.api.Test;
import org.snmp4j.smi.OID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SNMP table rows are paired by their index, not by position. Getting this wrong
 * silently attaches one route's netmask to another route, which reshapes the
 * network map.
 */
class SnmpScannerTests {

    @Test
    void fourElementSuffixIsTheAddressItself() {
        assertEquals("192.168.68.0", SnmpScanner.ipFromSuffix(new int[]{192, 168, 68, 0}));
        assertEquals("10.0.0.0", SnmpScanner.ipFromSuffix(new int[]{10, 0, 0, 0}));
    }

    @Test
    void longerSuffixCarriesTheAddressAtTheEnd() {
        // ipNetToMediaTable index: ifIndex + address
        assertEquals("192.168.1.20",
                SnmpScanner.ipFromSuffix(new int[]{7, 192, 168, 1, 20}));
    }

    @Test
    void suffixWithoutAnAddressIsRejected() {
        assertNull(SnmpScanner.ipFromSuffix(new int[]{1, 2, 3}));
        assertNull(SnmpScanner.ipFromSuffix(null));
    }

    @Test
    void outOfRangeOctetsAreRejected() {
        assertNull(SnmpScanner.ipFromSuffix(new int[]{192, 168, 1, 300}));
        assertNull(SnmpScanner.ipFromSuffix(new int[]{-1, 168, 1, 1}));
    }

    @Test
    void indexIsDecodedRelativeToTheRequestedColumn() {
        OID maskColumn = new OID("1.3.6.1.2.1.4.20.1.3");
        OID row = new OID("1.3.6.1.2.1.4.20.1.3.192.168.68.1");

        assertEquals("192.168.68.1", SnmpScanner.indexToIp(maskColumn, row));
    }

    @Test
    void indexDecoderIgnoresRowsFromTheColumnItself() {
        OID column = new OID("1.3.6.1.2.1.4.20.1.3");

        assertNull(SnmpScanner.indexToIp(column, column),
                "a bare column OID carries no index");
    }

    @Test
    void routeTypeInvalidIsTheRfc1213Value() {
        assertEquals("2", SnmpScanner.ROUTE_TYPE_INVALID);
    }
}
