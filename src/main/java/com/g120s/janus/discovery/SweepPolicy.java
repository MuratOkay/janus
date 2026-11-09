package com.g120s.janus.discovery;

/**
 * How much of a subnet to probe.
 *
 * <p>Sweeping every address of a large range is rarely affordable: a /16 holds
 * 65534 hosts and each one costs one connect attempt per probe port. Routers and
 * switches already know which addresses are in use, so asking them is both faster
 * and gentler on the network than guessing.
 */
public enum SweepPolicy {

    /**
     * Probe only addresses learned from SNMP tables (interface addresses, ARP
     * caches). Fastest and quietest, but reports nothing on a segment where no
     * SNMP-capable device was reachable.
     */
    KNOWN,

    /**
     * Probe the known addresses plus a bounded, deterministic sample of the
     * remaining range and the segment gateway. A compromise: catches hosts the
     * tables missed without sweeping everything.
     */
    SAMPLE,

    /**
     * Probe the whole range, up to {@code --max-hosts-per-subnet}. The exhaustive
     * default, and the only policy that finds silent hosts on a segment with no
     * SNMP data.
     */
    FULL;

    /** Parses a policy name, defaulting to {@link #FULL} when absent. */
    public static SweepPolicy parse(String value, String option) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(option + " must not be blank");
        }
        try {
            return valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(option + " must be one of known, sample, full (got: "
                    + value + ")", e);
        }
    }
}
