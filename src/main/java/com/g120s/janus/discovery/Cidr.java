package com.g120s.janus.discovery;

/**
 * Pure IPv4 CIDR helpers shared by configuration parsing and the discovery
 * orchestrator. Keeping the arithmetic in one place means a subnet learned from
 * SNMP, a seed on the command line and a route derived from LLDP all end up in
 * the same canonical {@code network/prefix} form, so they can be compared and
 * de-duplicated reliably.
 */
public final class Cidr {

    /** Smallest prefix accepted anywhere: below /8 a range stops being a LAN. */
    public static final int MIN_PREFIX = 8;

    private Cidr() {
    }

    /**
     * Rewrites a CIDR into its network address form, dropping host bits:
     * {@code 192.168.68.5/22 -> 192.168.68.0/22}.
     *
     * @throws IllegalArgumentException when the value is not a valid IPv4 CIDR
     */
    public static String normalize(String cidr) {
        long[] parsed = parse(cidr);
        return toIp(parsed[0] & maskOf((int) parsed[1])) + "/" + parsed[1];
    }

    /** Prefix length of a CIDR, for example {@code 22} for {@code 192.168.68.0/22}. */
    public static int prefix(String cidr) {
        return (int) parse(cidr)[1];
    }

    /**
     * Turns a dotted netmask into a prefix length. Non-contiguous masks return
     * {@code null} because they cannot be written as a prefix; some SNMP agents
     * do hand out such values.
     */
    public static Integer maskToPrefix(String mask) {
        Long value = parseIp(mask);
        if (value == null) return null;
        long inverted = ~value & 0xFFFFFFFFL;
        // A contiguous mask has a complement made only of trailing one bits, so
        // complement AND (complement + 1) is always zero.
        if ((inverted & (inverted + 1)) != 0) return null;
        return Long.bitCount(value);
    }

    /**
     * Builds a CIDR from an address and its netmask, for example
     * {@code ("192.168.1.10", "255.255.252.0") -> "192.168.0.0/22"}.
     *
     * @return {@code null} when either part is unusable or the prefix is too
     *         small to be a LAN
     */
    public static String fromMask(String addr, String mask) {
        Long value = parseIp(addr);
        Integer prefix = maskToPrefix(mask);
        if (value == null || prefix == null || prefix < MIN_PREFIX) return null;
        return toIp(value & maskOf(prefix)) + "/" + prefix;
    }

    /** Is {@code candidate} equal to or inside {@code supernet}? */
    public static boolean contains(String supernet, String candidate) {
        long[] sup;
        long[] cand;
        try {
            sup = parse(supernet);
            cand = parse(candidate);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (sup[1] > cand[1]) return false;
        long mask = maskOf((int) sup[1]);
        return (sup[0] & mask) == (cand[0] & mask);
    }

    /** Parses a dotted quad into an unsigned 32-bit value; {@code null} if malformed. */
    public static Long parseIp(String dotted) {
        if (dotted == null) return null;
        String[] octets = dotted.trim().split("\\.", -1);
        if (octets.length != 4) return null;
        long value = 0;
        for (String octet : octets) {
            int parsed;
            try {
                parsed = Integer.parseInt(octet.trim());
            } catch (NumberFormatException e) {
                return null;
            }
            if (parsed < 0 || parsed > 255) return null;
            value = (value << 8) | parsed;
        }
        return value;
    }

    /** Formats an unsigned 32-bit value as a dotted quad. */
    public static String toIp(long value) {
        return ((value >> 24) & 0xFF) + "." + ((value >> 16) & 0xFF) + "."
                + ((value >> 8) & 0xFF) + "." + (value & 0xFF);
    }

    private static long maskOf(int prefix) {
        return prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    }

    /** @return {@code {address, prefix}} */
    private static long[] parse(String cidr) {
        if (cidr == null) throw new IllegalArgumentException("Invalid CIDR: null");
        String[] parts = cidr.trim().split("/", -1);
        if (parts.length != 2) throw new IllegalArgumentException("Invalid CIDR: " + cidr);
        Long address = parseIp(parts[0]);
        if (address == null) throw new IllegalArgumentException("Invalid IPv4 CIDR: " + cidr);
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid IPv4 CIDR: " + cidr, e);
        }
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("Invalid IPv4 CIDR: " + cidr);
        }
        return new long[]{address, prefix};
    }
}
