package com.g120s.janus.model;

import java.util.ArrayList;
import java.util.List;

public class TopologyLink {
    public String protocol;
    public String localDevice;
    public String localMac;
    public String localIface;
    public Integer localVlan;
    public String remoteDevice;
    public String remoteChassisId;
    public String remotePort;
    public String remotePortDesc;
    public String remoteSystemName;
    public Integer remoteNativeVlan;
    public List<String> remoteMgmtIps = new ArrayList<>();
    public List<String> capabilities = new ArrayList<>();
    public long timestamp;
}
