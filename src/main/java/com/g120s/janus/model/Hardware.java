package com.g120s.janus.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Static hardware inventory for a device: how many CPUs it has, what type, how much
 * memory and which filesystems.
 *
 * <p>Every field is nullable and every collection may be empty. A device that does
 * not expose this information must report {@code null}, never {@code 0} — a zero
 * core count or a zero-sized disk reads as a real measurement and would be worse
 * than admitting the data was not available.
 */
public class Hardware {

    /** One mounted filesystem. {@code freeBytes} is null when usage was not reported. */
    public record Disk(String mount, String name, long totalBytes, Long freeBytes) { }

    public Integer cpuCores;
    public String cpuType;
    public Long memTotalBytes;
    public List<Disk> disks = new ArrayList<>();
    /** Where this came from: {@code snmp-hr}, {@code libvirt}, {@code vsphere}. */
    public String source;

    /** True when nothing at all was learned, so the field can be omitted from reports. */
    public boolean isEmpty() {
        return cpuCores == null && cpuType == null && memTotalBytes == null && disks.isEmpty();
    }
}
