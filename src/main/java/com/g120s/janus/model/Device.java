package com.g120s.janus.model;

import java.net.InetAddress;
import java.util.*;

public class Device {
    public enum Kind {
        UNKNOWN, WORKSTATION, SERVER, ROUTER, SWITCH, FIREWALL,
        PRINTER, IOT, MOBILE, STORAGE, VIRTUALIZATION_HOST, VIRTUAL_MACHINE
    }

    public InetAddress ip;
    public String mac; // aa:bb:cc:dd:ee:ff (küçük harf)
    public String hostname;
    public String vendor; // OUI lookup
    public Kind kind = Kind.UNKNOWN;
    public Set<Integer> openPorts = new TreeSet<>();
    public Set<String> services = new TreeSet<>();
    public Set<String> discoveredBy = new TreeSet<>(); // arp, tcp:22, snmp, mdns...
    public String osGuess;
    public String virtualizationType; // esxi, vcenter, proxmox, kvm, hyperv, xen, nutanix, virtualbox
    public String ownerHostId; // VM ise bağlı olduğu host kimliği (mac/ip/uuid)
    public Map<String, String> metadata = new HashMap<>();

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Device d))
            return false;
        return Objects.equals(ip, d.ip) && Objects.equals(mac, d.mac);
    }

    @Override public int hashCode() { return Objects.hash(ip, mac); }
}