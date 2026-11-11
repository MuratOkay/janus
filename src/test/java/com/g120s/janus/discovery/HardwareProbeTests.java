package com.g120s.janus.discovery;

import com.g120s.janus.model.Hardware;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HOST-RESOURCES-MIB is easy to read wrongly. The fixtures below are a verbatim
 * capture from a real net-snmp agent on an 8-core laptop, so the expected values
 * are the machine's actual values rather than guesses.
 */
class HardwareProbeTests {

    private static final String FIXED_DISK = SnmpScanner.HR_TYPE_FIXED_DISK;
    private static final String PROCESSOR = SnmpScanner.HR_DEVICE_PROCESSOR;

    @Test
    void readsCoresTypeMemoryAndDisksFromARealAgent() {
        Hardware hardware = HardwareProbe.fromSnmp(realAgent());

        assertNotNull(hardware);
        assertEquals(8, hardware.cpuCores, "the machine reports eight hrProcessorLoad rows");
        assertTrue(hardware.cpuType.contains("i5-8265U"), hardware.cpuType);
        // hrMemorySize is 7968560 KB, which is 7.6 GiB.
        assertEquals(7968560L * 1024, hardware.memTotalBytes);
        assertEquals("snmp-hr", hardware.source);
    }

    @Test
    void onlyRealFilesystemsAreReportedAsDisks() {
        // The regression this guards: hrStorageTable holds RAM, swap, caches and every
        // tmpfs mount, and tmpfs rows carry the same hrStorageFixedDisk type as /.
        Hardware hardware = HardwareProbe.fromSnmp(realAgent());

        List<String> mounts = hardware.disks.stream().map(Hardware.Disk::mount).toList();
        assertEquals(List.of("/", "/boot/efi"), mounts, "got " + mounts);
    }

    @Test
    void diskSizesMultiplyByAllocationUnits() {
        // / is 60984407 blocks of 4096 bytes = 232.6 GiB. Reporting the raw block count
        // would be wrong by a factor of 4096.
        Hardware hardware = HardwareProbe.fromSnmp(realAgent());
        Hardware.Disk root = hardware.disks.stream()
                .filter(d -> d.mount().equals("/")).findFirst().orElseThrow();

        assertEquals(60984407L * 4096, root.totalBytes());
        assertTrue(root.freeBytes() > 0);
        assertTrue(root.freeBytes() < root.totalBytes());
    }

    @Test
    void networkInterfacesDoNotCountAsCpus() {
        // hrDeviceTable mixes processors with NICs; four NIC rows would inflate an
        // 8-core machine to twelve "cores".
        Hardware hardware = HardwareProbe.fromSnmp(realAgent());

        assertEquals(8, hardware.cpuCores);
        assertFalse(hardware.cpuType.startsWith("network interface"), hardware.cpuType);
    }

    @Test
    void aDeviceWithoutHostResourcesReportsNullNotZeroes() {
        assertNull(HardwareProbe.fromSnmp(null), "no tables means no inventory");
        assertNull(HardwareProbe.fromSnmp(emptyAgent()),
                "an empty table must not produce a device with 0 cores and 0 bytes");
    }

    @Test
    void isEmptyDistinguishesUnknownFromZero() {
        Hardware blank = new Hardware();
        assertTrue(blank.isEmpty());

        blank.cpuCores = 0;
        assertFalse(blank.isEmpty(), "an explicit zero is data, however unlikely");
    }

    @Test
    void virtualMountsAreRecognised() {
        assertAll(
                () -> assertTrue(HardwareProbe.isVirtualMount("/run")),
                () -> assertTrue(HardwareProbe.isVirtualMount("/dev/shm")),
                () -> assertTrue(HardwareProbe.isVirtualMount("/run/user/1000")),
                () -> assertTrue(HardwareProbe.isVirtualMount("/sys/fs/cgroup")),
                () -> assertFalse(HardwareProbe.isVirtualMount("/")),
                () -> assertFalse(HardwareProbe.isVirtualMount("/boot/efi")),
                () -> assertFalse(HardwareProbe.isVirtualMount("/home"))
        );
    }

    @Test
    void oidsAreAcceptedWithOrWithoutALeadingDot() {
        assertEquals(FIXED_DISK, HardwareProbe.normalizeOid("." + FIXED_DISK));
        assertEquals(FIXED_DISK, HardwareProbe.normalizeOid(FIXED_DISK));
        assertNull(HardwareProbe.normalizeOid(null));
    }

    @Test
    void malformedNumbersAreIgnoredRatherThanZeroed() {
        assertNull(HardwareProbe.parseLong("not-a-number"));
        assertNull(HardwareProbe.parseLong(null));
        assertEquals(42L, HardwareProbe.parseLong(" 42 "));
    }

    // -- fixtures ---------------------------------------------------------

    private static SnmpScanner.HostResources emptyAgent() {
        return new SnmpScanner.HostResources(null, Map.of(), Map.of(), Map.of(), Map.of(),
                Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of());
    }

    /** Verbatim capture from net-snmp on this machine. */
    private static SnmpScanner.HostResources realAgent() {
        Map<String,String> storageTypes = new LinkedHashMap<>();
        storageTypes.put("1", ".1.3.6.1.2.1.25.2.1.2");    // virtual memory
        storageTypes.put("10", ".1.3.6.1.2.1.25.2.1.3");   // swap
        storageTypes.put("35", "." + FIXED_DISK);
        storageTypes.put("36", "." + FIXED_DISK);
        storageTypes.put("38", "." + FIXED_DISK);
        storageTypes.put("39", "." + FIXED_DISK);
        storageTypes.put("110", "." + FIXED_DISK);
        storageTypes.put("111", "." + FIXED_DISK);
        storageTypes.put("116", "." + FIXED_DISK);

        Map<String,String> descriptions = new LinkedHashMap<>();
        descriptions.put("1", "Physical memory");
        descriptions.put("10", "Swap space");
        descriptions.put("35", "tmpfs");
        descriptions.put("36", "ext4");
        descriptions.put("38", "tmpfs");
        descriptions.put("39", "tmpfs");
        descriptions.put("110", "vfat");
        descriptions.put("111", "tmpfs");
        descriptions.put("116", "tmpfs");

        Map<String,String> units = new LinkedHashMap<>();
        for (String index : storageTypes.keySet()) {
            units.put(index, index.equals("10") ? "1024" : "4096");
        }

        Map<String,String> sizes = new LinkedHashMap<>();
        sizes.put("1", "7968560");
        sizes.put("10", "4194300");
        sizes.put("35", "199214");
        sizes.put("36", "60984407");
        sizes.put("38", "996070");
        sizes.put("39", "1280");
        sizes.put("110", "274658");
        sizes.put("111", "199214");
        sizes.put("116", "199214");

        Map<String,String> used = new LinkedHashMap<>();
        used.put("1", "7000000");
        used.put("10", "100");
        used.put("35", "100");
        used.put("36", "34020000");
        used.put("38", "10");
        used.put("39", "1");
        used.put("110", "1000");
        used.put("111", "1");
        used.put("116", "1");

        // hrDeviceTable: eight Intel cores followed by four network interfaces.
        Map<String,String> deviceTypes = new LinkedHashMap<>();
        Map<String,String> deviceDescriptions = new LinkedHashMap<>();
        Map<String,String> processorLoads = new LinkedHashMap<>();
        int[] cpuIndexes = {196608, 196609, 196610, 196611, 196612, 196613, 196614, 196615};
        for (int index : cpuIndexes) {
            deviceTypes.put(String.valueOf(index), "." + PROCESSOR);
            deviceDescriptions.put(String.valueOf(index),
                    "GenuineIntel: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz");
            processorLoads.put(String.valueOf(index), "10");
        }
        String[] nics = {"lo", "eno2", "wlo1", "docker0"};
        int nicIndex = 262145;
        for (String nic : nics) {
            deviceTypes.put(String.valueOf(nicIndex), ".1.3.6.1.2.1.25.3.1.4");
            deviceDescriptions.put(String.valueOf(nicIndex), "network interface " + nic);
            nicIndex++;
        }

        // hrFSTable: the tmpfs mounts plus the two real filesystems.
        Map<String,String> fsMounts = new LinkedHashMap<>();
        Map<String,String> fsStorage = new LinkedHashMap<>();
        fsMounts.put("5", "/run");            fsStorage.put("5", "35");
        fsMounts.put("6", "/");               fsStorage.put("6", "36");
        fsMounts.put("8", "/dev/shm");        fsStorage.put("8", "38");
        fsMounts.put("9", "/run/lock");       fsStorage.put("9", "39");
        fsMounts.put("80", "/boot/efi");      fsStorage.put("80", "110");
        fsMounts.put("81", "/run/snapd/ns");  fsStorage.put("81", "111");
        fsMounts.put("86", "/run/user/1000"); fsStorage.put("86", "116");

        return new SnmpScanner.HostResources("7968560", storageTypes, descriptions, units, sizes,
                used, deviceTypes, deviceDescriptions, processorLoads, fsMounts, fsStorage);
    }
}
