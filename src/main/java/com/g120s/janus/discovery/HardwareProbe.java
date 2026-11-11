package com.g120s.janus.discovery;

import com.g120s.janus.model.Hardware;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns HOST-RESOURCES-MIB tables into a {@link Hardware} inventory.
 *
 * <p>The raw tables are misleading on their own. Verified against a real net-snmp
 * agent, three rules are needed to avoid nonsense:
 *
 * <ul>
 *   <li>{@code hrStorageTable} is not a disk list — it holds RAM, swap, caches and
 *       network mounts. Filtering on {@code hrStorageType = hrStorageFixedDisk} is
 *       <em>still</em> not enough, because {@code tmpfs} mounts carry that same
 *       type, so virtual mount points must be excluded as well.</li>
 *   <li>Sizes are {@code hrStorageSize × hrStorageAllocationUnits}; using the raw
 *       count is wrong by a factor of the block size (4096 on Linux).</li>
 *   <li>{@code hrDeviceTable} mixes CPUs with network interfaces, so processor
 *       rows must be selected by {@code hrDeviceType = hrDeviceProcessor}.</li>
 * </ul>
 */
public final class HardwareProbe {

    /**
     * Mount points that are never real storage: tmpfs, cgroup, overlay and friends
     * report a fixed-disk type but occupy RAM.
     */
    private static final Set<String> VIRTUAL_MOUNTS = Set.of(
            "/run", "/run/lock", "/run/shm", "/dev/shm", "/run/snapd/ns",
            "/sys", "/proc", "/dev", "/dev/pts", "/sys/fs/cgroup");

    private HardwareProbe() {
    }

    /** Builds the inventory, or {@code null} when nothing usable was reported. */
    public static Hardware fromSnmp(SnmpScanner.HostResources resources) {
        if (resources == null || resources.isEmpty()) return null;

        Hardware hardware = new Hardware();
        hardware.source = "snmp-hr";

        // hrMemorySize is reported in kilobytes.
        Long memoryKb = parseLong(resources.memorySizeKb());
        if (memoryKb != null && memoryKb > 0) hardware.memTotalBytes = memoryKb * 1024L;

        List<String> cpuDescriptions = cpuDescriptions(resources);
        if (!cpuDescriptions.isEmpty()) {
            hardware.cpuCores = cpuDescriptions.size();
            hardware.cpuType = cpuDescriptions.get(0);
        }

        hardware.disks = disks(resources);
        return hardware.isEmpty() ? null : hardware;
    }

    /**
     * One entry per processor row: the count is the core count, while every entry
     * carries the same model string because the agent repeats it per core.
     */
    static List<String> cpuDescriptions(SnmpScanner.HostResources resources) {
        List<String> descriptions = new ArrayList<>();
        for (String index : resources.processorLoads().keySet()) {
            String type = normalizeOid(resources.deviceTypes().get(index));
            // Without this filter network interfaces count as CPUs: a real 8-core
            // laptop reported 12 rows, 4 of them "network interface ...".
            if (type == null || !type.equals(SnmpScanner.HR_DEVICE_PROCESSOR)) continue;
            String description = resources.deviceDescriptions().get(index);
            descriptions.add(description == null ? "" : description.trim());
        }
        return descriptions;
    }

    /** Real filesystems, joined from hrFSTable to hrStorageTable by storage index. */
    static List<Hardware.Disk> disks(SnmpScanner.HostResources resources) {
        List<Hardware.Disk> disks = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Map.Entry<String, String> mount : resources.fsMountPoints().entrySet()) {
            String mountPoint = mount.getValue();
            if (mountPoint == null || mountPoint.isBlank()) continue;
            if (isVirtualMount(mountPoint)) continue;

            String storageIndex = resources.fsStorageIndexes().get(mount.getKey());
            if (storageIndex == null) continue;
            // tmpfs rows are typed fixed-disk too, so the mount check above is what
            // actually removes them; this guard covers other odd agents.
            String type = normalizeOid(resources.storageTypes().get(storageIndex));
            if (type != null && !type.equals(SnmpScanner.HR_TYPE_FIXED_DISK)) continue;

            Long units = parseLong(resources.storageAllocationUnits().get(storageIndex));
            Long size = parseLong(resources.storageSizes().get(storageIndex));
            if (size == null || units == null || size <= 0 || units <= 0) continue;
            long totalBytes = size * units;
            Long used = parseLong(resources.storageUsed().get(storageIndex));
            Long freeBytes = used == null ? null : Math.max(0, totalBytes - used * units);

            if (!seen.add(mountPoint)) continue;
            disks.add(new Hardware.Disk(mountPoint,
                    resources.storageDescriptions().get(storageIndex), totalBytes, freeBytes));
        }
        return disks;
    }

    /** Is this a RAM-backed or kernel pseudo filesystem rather than real storage? */
    static boolean isVirtualMount(String mountPoint) {
        if (VIRTUAL_MOUNTS.contains(mountPoint)) return true;
        return mountPoint.startsWith("/run/") || mountPoint.startsWith("/sys/")
                || mountPoint.startsWith("/proc/") || mountPoint.startsWith("/dev/");
    }

    /** SNMP OIDs arrive either bare ({@code 1.3.6...}) or dot-prefixed. */
    static String normalizeOid(String oid) {
        if (oid == null) return null;
        String trimmed = oid.trim();
        return trimmed.startsWith(".") ? trimmed.substring(1) : trimmed;
    }

    static Long parseLong(String value) {
        if (value == null) return null;
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
