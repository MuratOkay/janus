package com.g120s.janus.virtualization;

import com.g120s.janus.model.*;

import java.net.InetAddress;
import java.util.*;

public final class VMHostMatcher {

    /**
     * Two layers:
     * 1) Exact: the virtualization API linked the VM's MAC to a host (vhost.vmMacs).
     * 2) Heuristic: MAC OUI + being on the same L2 segment + name pattern.
     */
    public static void match(DiscoveryResult r) {
        Map<String, String> macToHost = new HashMap<>();
        for (VirtualizationHost h : r.vhosts)
            for (String mac : h.vmMacs) macToHost.put(normalizeMac(mac), h.id);

        for (Device d : r.devices) {
            String vmType = VirtualizationDetector.vmVendorByMac(d.mac);
            if (d.kind == Device.Kind.VIRTUALIZATION_HOST) continue;
            if (vmType != null) d.kind = Device.Kind.VIRTUAL_MACHINE;

            String mac = normalizeMac(d.mac);
            if (mac != null && macToHost.containsKey(mac)) {
                d.ownerHostId = macToHost.get(mac);
                d.metadata.put("match", "api-mac");
            } else if (vmType != null) {
                d.metadata.put("vmVendor", vmType);
                // Heuristic: a VM vendor host matching in the same /24
                for (VirtualizationHost h : r.vhosts) {
                    if (sameL2(h, d)) {
                        d.ownerHostId = h.id;
                        d.metadata.put("match", "heuristic-l2-oui");
                        break;
                    }
                }
            }
        }

        // VM IP enrichment: assign an IP to the VM from the device matching its MAC
        Map<String, Device> devicesByMac = new HashMap<>();
        for (Device device : r.devices) {
            String devMac = normalizeMac(device.mac);
            if (devMac != null) devicesByMac.put(devMac, device);
        }
        for (VirtualMachine vm : r.vms) {
            Device device = devicesByMac.get(normalizeMac(vm.mac));
            if (device != null && vm.ip == null && device.ip != null) {
                vm.ip = device.ip.getHostAddress();
            }
        }
    }

    private static boolean sameL2(VirtualizationHost h, Device d) {
        if (h.managementNets.isEmpty() || d.ip == null) return false;
        for (String net : h.managementNets) {
            try {
                String[] parts = net.split("/");
                int prefix = Integer.parseInt(parts[1]);
                if (prefix < 0 || prefix > 32) continue;
                InetAddress network = InetAddress.getByName(parts[0]);
                InetAddress device = d.ip;
                if (network.getAddress().length != 4 || device.getAddress().length != 4) continue;
                int mask = prefix == 0 ? 0 : (int) (0xffff_ffffL << (32 - prefix));
                if ((toInt(network) & mask) == (toInt(device) & mask)) return true;
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    private static String normalizeMac(String mac) {
        return mac == null ? null : mac.replace("-", ":").toLowerCase(Locale.ROOT);
    }

    private static int toInt(InetAddress address) {
        byte[] bytes = address.getAddress();
        return ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16)
                | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
    }
}
