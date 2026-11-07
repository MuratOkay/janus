package com.g120s.janus.l2;

import java.util.*;

public class NeighborRecord {
    public enum Protocol { LLDP, CDP }
    public enum Capability {
        OTHER, REPEATER, BRIDGE, SWITCH, WLAN_AP, ROUTER,
        TELEPHONE, DOCSIS, STATION, C_VLAN, S_VLAN, TWO_PORT_BRIDGE
    }

    public Protocol protocol;
    public long timestamp;
    public String localIface;
    public String localMac;
    public Integer localVlan;
    public String remoteChassisId;
    public String remoteChassisType;
    public String remotePortId;
    public String remotePortType;
    public String remotePortDesc;
    public String remoteSystemName;
    public String remoteSystemDesc;
    public Set<String> remoteMgmtIps = new LinkedHashSet<>();
    public Set<Capability> remoteCapabilities = EnumSet.noneOf(Capability.class);
    public Integer remoteNativeVlan;
    public Integer remoteVlanId;
    public String remoteVlanName;
    public Integer ttl;
    public Map<String, String> extras = new LinkedHashMap<>();
}
