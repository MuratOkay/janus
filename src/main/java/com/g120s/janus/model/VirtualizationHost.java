package com.g120s.janus.model;

import java.util.*;

public class VirtualizationHost {
    public String id;             // uuid / mac / ip
    public String type;           // esxi, vcenter, proxmox, kvm, hyperv, xen, nutanix
    public String ip, name, version, source;
    public Set<String> vmMacs = new TreeSet<>();   // yönetilen VM'lerin MAC'leri
    public Set<String> managementNets = new TreeSet<>();  // host VMkernel/bridge subnetleri
    public Map<String, String> metadata = new HashMap<>();
}