package com.g120s.janus.l2;

import com.g120s.janus.model.*;

import java.net.InetAddress;
import java.util.*;

public final class TopologyBuilder {
    private TopologyBuilder() {}

    public static void apply(DiscoveryResult result, List<NeighborRecord> neighbors) {
        Map<String, Device> byIp = new HashMap<>();
        Map<String, Device> byMac = new HashMap<>();
        for (Device device : result.devices) {
            if (device.ip != null) byIp.put(device.ip.getHostAddress(), device);
            if (device.mac != null) byMac.put(device.mac.toLowerCase(Locale.ROOT), device);
        }
        Set<String> existingLinks = new HashSet<>();
        for (TopologyLink link : result.links) {
            existingLinks.add(linkKey(link.protocol, link.localMac, link.remoteChassisId, link.remotePort));
        }

        for (NeighborRecord neighbor : neighbors) {
            Device local = neighbor.localMac == null ? null
                    : byMac.get(neighbor.localMac.toLowerCase(Locale.ROOT));
            Device remote = findRemote(neighbor, byIp, byMac, result.devices);

            TopologyLink link = new TopologyLink();
            link.protocol = neighbor.protocol.name();
            link.localDevice = deviceId(local);
            link.localMac = neighbor.localMac;
            link.localIface = neighbor.localIface;
            link.localVlan = neighbor.localVlan;
            link.remoteDevice = deviceId(remote);
            link.remoteChassisId = neighbor.remoteChassisId;
            link.remotePort = neighbor.remotePortId;
            link.remotePortDesc = neighbor.remotePortDesc;
            link.remoteSystemName = neighbor.remoteSystemName;
            link.remoteNativeVlan = neighbor.remoteNativeVlan;
            link.remoteMgmtIps = new ArrayList<>(neighbor.remoteMgmtIps);
            link.capabilities = neighbor.remoteCapabilities.stream().map(Enum::name).toList();
            link.timestamp = neighbor.timestamp;
            String key = linkKey(link.protocol, link.localMac, link.remoteChassisId, link.remotePort);
            if (existingLinks.add(key)) result.links.add(link);

            if (remote != null) {
                if (neighbor.remoteCapabilities.contains(NeighborRecord.Capability.ROUTER)) {
                    remote.kind = Device.Kind.ROUTER;
                } else if (remote.kind == Device.Kind.UNKNOWN
                        && (neighbor.remoteCapabilities.contains(NeighborRecord.Capability.SWITCH)
                        || neighbor.remoteCapabilities.contains(NeighborRecord.Capability.BRIDGE))) {
                    remote.kind = Device.Kind.SWITCH;
                }
                if (remote.hostname == null) remote.hostname = neighbor.remoteSystemName;
                if (!remote.metadata.containsKey("sysDescr") && neighbor.remoteSystemDesc != null) {
                    remote.metadata.put("sysDescr", neighbor.remoteSystemDesc);
                }
                if (neighbor.remotePortId != null) {
                    remote.metadata.put("lldp." + neighbor.protocol.name().toLowerCase(Locale.ROOT) + ".port",
                            neighbor.remotePortId);
                }
                if (neighbor.remoteNativeVlan != null) {
                    remote.metadata.put("nativeVlan", String.valueOf(neighbor.remoteNativeVlan));
                }
                remote.discoveredBy.add(neighbor.protocol.name().toLowerCase(Locale.ROOT));
            }

            for (String address : neighbor.remoteMgmtIps) {
                if (byIp.containsKey(address)) continue;
                try {
                    Device discovered = new Device();
                    discovered.ip = InetAddress.getByName(address);
                    discovered.kind = Device.Kind.SWITCH;
                    discovered.discoveredBy.add("lldp-mgmt");
                    discovered.hostname = neighbor.remoteSystemName;
                    if (neighbor.remoteNativeVlan != null) {
                        discovered.metadata.put("nativeVlan", String.valueOf(neighbor.remoteNativeVlan));
                    }
                    result.devices.add(discovered);
                    byIp.put(address, discovered);
                } catch (Exception e) {
                    result.warnings.add("Geçersiz LLDP/CDP yönetim IP'si '" + address + "': " + e.getMessage());
                }
            }

            if (local != null && neighbor.localVlan != null) {
                local.metadata.put("vlan." + neighbor.localVlan,
                        "iface=" + neighbor.localIface + " remote=" + neighbor.remoteSystemName);
            }
        }
    }

    private static Device findRemote(NeighborRecord neighbor, Map<String, Device> byIp,
                                     Map<String, Device> byMac, List<Device> devices) {
        if ("mac".equals(neighbor.remoteChassisType) && neighbor.remoteChassisId != null) {
            Device found = byMac.get(neighbor.remoteChassisId.toLowerCase(Locale.ROOT));
            if (found != null) return found;
        }
        for (String address : neighbor.remoteMgmtIps) {
            Device found = byIp.get(address);
            if (found != null) return found;
        }
        if (neighbor.remoteSystemName != null) {
            for (Device device : devices) {
                if (neighbor.remoteSystemName.equalsIgnoreCase(device.hostname)) return device;
            }
        }
        return null;
    }

    private static String deviceId(Device device) {
        if (device == null) return null;
        if (device.ip != null) return device.ip.getHostAddress();
        return device.mac;
    }

    private static String linkKey(String protocol, String localMac, String chassis, String port) {
        return protocol + "|" + localMac + "|" + chassis + "|" + port;
    }
}
