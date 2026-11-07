package com.g120s.janus.model;

import java.util.*;
public class NetworkSegment {
    public String cidr;            // 10.0.5.0/24
    public String gateway;
    public String vlan;
    public String description;
    public Set<String> discoveredBy = new TreeSet<>();  // iface, snmp-route, lldp, dhcp, vmware-portgroup...
    public NetworkSegment(String cidr) { this.cidr = cidr; }
}