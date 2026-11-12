package com.g120s.janus.virtualization;

import com.g120s.janus.model.Hardware;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Redfish returns a deeply nested {@code ComputerSystem} resource. The values are
 * spread across {@code ProcessorSummary}, {@code MemorySummary} and inline links to
 * further collections, so parsing needs to be exact rather than optimistic.
 */
class RedfishDiscoveryTests {

    private static final ObjectMapper MAP = new ObjectMapper();

    @Test
    void mapsASystemResourceOntoTheInventory() throws Exception {
        Hardware hardware = RedfishDiscovery.fromSystem(system());

        assertEquals("PowerEdge R640", hardware.model);
        assertEquals("ABC1234", hardware.serial);
        assertEquals(32, hardware.cpuCores);
        assertEquals("Intel(R) Xeon(R) Gold 6248", hardware.cpuType);
        // Redfish reports total memory in GiB, not bytes.
        assertEquals(128L * 1024 * 1024 * 1024, hardware.memTotalBytes);
        assertEquals("redfish", hardware.source);
    }

    @Test
    void missingFieldsStayNullRatherThanBecomingZero() throws Exception {
        // A minimal BMC that only reports a model must not claim 0 cores and 0 bytes.
        Hardware hardware = RedfishDiscovery.fromSystem(
                MAP.readTree("{\"Model\":\"Minimal\",\"SerialNumber\":\"X1\"}"));

        assertEquals("Minimal", hardware.model);
        assertNull(hardware.cpuCores);
        assertNull(hardware.cpuType);
        assertNull(hardware.memTotalBytes);
        assertFalse(hardware.isEmpty());
    }

    @Test
    void anEmptySystemIsEmptyNotZeroed() throws Exception {
        Hardware hardware = RedfishDiscovery.fromSystem(MAP.readTree("{}"));

        assertTrue(hardware.isEmpty(), "nothing reported must mean nothing reported");
    }

    @Test
    void modelFallsBackToNameWhenAbsent() throws Exception {
        // Some virtual BMCs omit Model but carry a useful Name.
        Hardware hardware = RedfishDiscovery.fromSystem(
                MAP.readTree("{\"Name\":\"ProLiant DL380 Gen10\"}"));

        assertEquals("ProLiant DL380 Gen10", hardware.model);
    }

    @Test
    void relativeOdataIdsResolveAgainstTheServiceRoot() {
        assertEquals("https://bmc/redfish/v1/Systems/1",
                RedfishDiscovery.absolute("https://bmc", "/redfish/v1/Systems/1"));
        assertEquals("https://bmc/redfish/v1/Systems/1",
                RedfishDiscovery.absolute("https://bmc", "redfish/v1/Systems/1"));
        // An absolute URL must pass through untouched.
        assertEquals("https://other/redfish/v1",
                RedfishDiscovery.absolute("https://bmc", "https://other/redfish/v1"));
        assertNull(RedfishDiscovery.absolute("https://bmc", null));
    }

    @Test
    void firstMemberUrlFindsTheSystem() throws Exception {
        JsonNode collection = MAP.readTree("""
                {"Members":[{"@odata.id":"/redfish/v1/Systems/437XR1138R2"}]}
                """);

        assertEquals("/redfish/v1/Systems/437XR1138R2",
                RedfishDiscovery.firstMemberUrl(collection));
    }

    @Test
    void emptyOrAbsentCollectionsYieldNoSystemUrl() throws Exception {
        assertNull(RedfishDiscovery.firstMemberUrl(MAP.readTree("{\"Members\":[]}")));
        assertNull(RedfishDiscovery.firstMemberUrl(MAP.readTree("{}")));
        assertNull(RedfishDiscovery.firstMemberUrl(null));
    }

    @Test
    void optionsCarryCredentialsAndPort() {
        RedfishDiscovery.Options options =
                new RedfishDiscovery.Options("bmc.example", 443, "admin", "secret", true);

        assertEquals("bmc.example", options.host());
        assertEquals(443, options.port());
        assertTrue(options.ignoreCert(), "BMCs commonly use self-signed certificates");
    }

    /** A realistic ComputerSystem resource, trimmed to the fields we read. */
    private static JsonNode system() throws Exception {
        return MAP.readTree("""
                {
                  "@odata.id": "/redfish/v1/Systems/1",
                  "Name": "System",
                  "Model": "PowerEdge R640",
                  "SerialNumber": "ABC1234",
                  "ProcessorSummary": { "Count": 2, "CoreCount": 32,
                                        "Model": "Intel(R) Xeon(R) Gold 6248" },
                  "MemorySummary": { "TotalSystemMemoryGiB": 128 },
                  "Storage": { "@odata.id": "/redfish/v1/Systems/1/Storage" }
                }
                """);
    }
}
