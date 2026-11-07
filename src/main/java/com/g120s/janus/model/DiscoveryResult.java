package com.g120s.janus.model;

import java.util.*;

public class DiscoveryResult {
    public List<NetworkSegment> segments = new ArrayList<>();
    public List<Device> devices = new ArrayList<>();
    public List<VirtualMachine> vms = new ArrayList<>();
    public List<VirtualizationHost> vhosts = new ArrayList<>();
    public List<TopologyLink> links = new ArrayList<>();
    public List<String> warnings = new ArrayList<>();
    public long startedAt, finishedAt;
}