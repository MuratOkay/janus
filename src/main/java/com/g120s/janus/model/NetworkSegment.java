package com.g120s.janus.model;

import java.util.*;
public class NetworkSegment {
    public String cidr;            // 10.0.5.0/24
    public String gateway;
    public String vlan;
    public String description;
    public String parentCidr;      // segment that led here; null for seeds
    public int depth;              // hops from a seed, 0 for seeds themselves
    public String coveredBy;       // wider already-crawled segment holding this range
    public int hostsProbed;        // addresses actually probed
    public long hostsTotal;        // usable addresses in the range
    public String sweepPolicy;     // how the range was probed: known, sample or full
    public Set<String> discoveredBy = new TreeSet<>();  // iface, snmp-route, lldp, dhcp, vmware-portgroup...
    public NetworkSegment(String cidr) { this.cidr = cidr; }
}