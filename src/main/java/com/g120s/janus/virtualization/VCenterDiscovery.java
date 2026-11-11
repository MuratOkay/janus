package com.g120s.janus.virtualization;

import com.vmware.vim25.*;
import com.vmware.vim25.mo.*;
import com.g120s.janus.model.VirtualizationHost;

import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.util.*;

public final class VCenterDiscovery {

    public record Options(String url, String user, String pass, boolean ignoreCert) {}

    public static List<VirtualizationHost> discover(
            Options opt, List<com.g120s.janus.model.VirtualMachine> vmSink)
            throws Exception {
        List<VirtualizationHost> result = new ArrayList<>();
        String url = normalizeUrl(opt.url());
        URL sdkUrl = URI.create(url).toURL();
        String vcHost = sdkUrl.getHost();

        ServiceInstance si = new ServiceInstance(
                sdkUrl, opt.user(), opt.pass(), opt.ignoreCert());
        try {
            // ---- vCenter (or standalone ESXi) itself
            AboutInfo about = si.getAboutInfo();
            VirtualizationHost vc = new VirtualizationHost();
            vc.type = "vcenter";
            vc.source = "api";
            vc.id = "vcenter:" + vcHost;
            vc.ip = vcHost;
            vc.name = about.getFullName();
            vc.version = about.getVersion() + " build " + about.getBuild();
            vc.metadata.put("apiType", about.getApiType());
            vc.metadata.put("apiVersion", about.getApiVersion());
            vc.metadata.put("osType", about.getOsType());
            result.add(vc);

            Folder root = si.getRootFolder();
            InventoryNavigator nav = new InventoryNavigator(root);

            // ---- Resolve Distributed vSwitch portgroup names (dvpg key → name)
            Map<String, String> dvPgNames = new HashMap<>();
            for (ManagedEntity me : safeArray(nav.searchManagedEntities("DistributedVirtualPortgroup")))
                if (me instanceof DistributedVirtualPortgroup pg)
                    dvPgNames.put(pg.getKey(), pg.getName());

            // ---- Hosts
            Map<String, VirtualizationHost> byMor = new LinkedHashMap<>();
            for (ManagedEntity me : safeArray(nav.searchManagedEntities("HostSystem"))) {
                HostSystem hs = (HostSystem) me;
                VirtualizationHost vh = buildHostVHost(hs, si, vc, dvPgNames);
                result.add(vh);
                byMor.put(hs.getMOR().getVal(), vh);
            }

            // ---- VMs
            for (ManagedEntity me : safeArray(nav.searchManagedEntities("VirtualMachine"))) {
                com.vmware.vim25.mo.VirtualMachine vmo = (com.vmware.vim25.mo.VirtualMachine) me;
                com.g120s.janus.model.VirtualMachine vm = buildVm(vmo, dvPgNames);

                ManagedObjectReference hostRef = vmo.getRuntime() != null
                        ? vmo.getRuntime().getHost() : null;
                if (hostRef != null) {
                    VirtualizationHost vh = byMor.get(hostRef.getVal());
                    if (vh != null) {
                        vm.hostId = vh.id;
                        for (String nic : vm.nics) {
                            int at = nic.indexOf('@');
                            String mac = at > 0 ? nic.substring(0, at) : nic;
                            if (!"no-mac".equals(mac)) vh.vmMacs.add(mac);
                        }
                    }
                }
                vmSink.add(vm);
            }
        } finally {
            try { si.getServerConnection().logout(); } catch (Exception ignored) {}
        }
        return result;
    }

    // ===================== Host =====================
    private static VirtualizationHost buildHostVHost(HostSystem hs, ServiceInstance si,
                                                     VirtualizationHost vc,
                                                     Map<String, String> dvPgNames) {
        VirtualizationHost vh = new VirtualizationHost();
        vh.type = "esxi";
        vh.source = "api";
        vh.name = hs.getName();
        vh.metadata.put("vcenter", vc.ip);

        // Product version
        try {
            if (hs.getConfig() != null && hs.getConfig().getProduct() != null) {
                AboutInfo pi = hs.getConfig().getProduct();
                vh.version = pi.getFullName();          // "VMware ESXi 7.0.3 build-... "
                vh.metadata.put("vendor", pi.getVendor());
                vh.metadata.put("product", pi.getName());
                vh.metadata.put("build", pi.getBuild());
                vh.metadata.put("apiVersion", pi.getApiVersion());
            }
        } catch (Exception ignored) {}

        // CPU and memory come from the host summary we already hold, so this costs no
        // extra round trip. cpuModel is the real model string, unlike the raw speed.
        try {
            if (hs.getSummary() != null && hs.getSummary().getHardware() != null) {
                com.vmware.vim25.HostHardwareSummary info = hs.getSummary().getHardware();
                com.g120s.janus.model.Hardware hardware = new com.g120s.janus.model.Hardware();
                if (info.getNumCpuCores() > 0) hardware.cpuCores = (int) info.getNumCpuCores();
                if (info.getCpuModel() != null && !info.getCpuModel().isBlank()) {
                    hardware.cpuType = info.getCpuModel();
                }
                if (info.getMemorySize() > 0) hardware.memTotalBytes = info.getMemorySize();
                hardware.source = "vsphere";
                if (!hardware.isEmpty()) vh.hardware = hardware;
            }
        } catch (Exception ignored) {}

        // Runtime state
        try {
            if (hs.getRuntime() != null) {
                if (hs.getRuntime().getConnectionState() != null)
                    vh.metadata.put("connectionState", hs.getRuntime().getConnectionState().toString());
                if (hs.getRuntime().getPowerState() != null)
                    vh.metadata.put("powerState", hs.getRuntime().getPowerState().toString());
            }
        } catch (Exception ignored) {}

        // Parent chain: Cluster / ComputeResource / Datacenter
        try {
            ManagedEntity cur = hs;
            while (cur != null && cur.getParent() != null) {
                ManagedEntity parent = cur.getParent();
                if (parent instanceof ClusterComputeResource cl) {
                    vh.metadata.put("cluster", cl.getName());
                    vh.metadata.put("clusterId", cl.getMOR().getVal());
                    ComputeResourceConfigInfo conf = null;
                    try { conf = cl.getConfigurationEx(); } catch (Exception ignored) {}
                    if (conf instanceof ClusterConfigInfoEx cc
                            && cc.getDrsConfig() != null
                            && cc.getDrsConfig().getEnabled() != null) {
                        vh.metadata.put("drs", cc.getDrsConfig().getEnabled().toString());
                    }
                } else if (parent instanceof ComputeResource cr) {
                    vh.metadata.put("computeResource", cr.getName());
                } else if (parent instanceof Datacenter dc) {
                    vh.metadata.put("datacenter", dc.getName());
                    break;
                }
                cur = parent;
            }
        } catch (Exception ignored) {}

        // VMkernel & console vmks + vSwitch/portgroup list
        try {
            HostNetworkInfo ni = hs.getConfig().getNetwork();
            if (ni != null) {
                if (ni.getVnic() != null) {
                    for (int i = 0; i < ni.getVnic().length; i++) {
                        HostVirtualNic vnic = ni.getVnic()[i];
                        HostVirtualNicSpec spec = vnic.getSpec();
                        if (spec != null && spec.getIp() != null) {
                            String ip = spec.getIp().getIpAddress();
                            int prefix = prefixLength(spec.getIp().getSubnetMask());
                            vh.managementNets.add(ip + "/" + prefix);
                            vh.metadata.put("vmk" + i, vnic.getDevice() + "=" + ip + "/" + prefix);
                        }
                    }
                }
                if (ni.getConsoleVnic() != null) {
                    for (HostVirtualNic vnic : ni.getConsoleVnic()) {
                        HostVirtualNicSpec spec = vnic.getSpec();
                        if (spec != null && spec.getIp() != null)
                            vh.managementNets.add(
                                    spec.getIp().getIpAddress() + "/"
                                            + prefixLength(spec.getIp().getSubnetMask()));
                    }
                }
                if (ni.getVswitch() != null) {
                    List<String> vs = new ArrayList<>();
                    for (HostVirtualSwitch s : ni.getVswitch()) vs.add(s.getName());
                    vh.metadata.put("vswitches", String.join(",", vs));
                }
                if (ni.getPortgroup() != null) {
                    List<String> pgs = new ArrayList<>();
                    for (HostPortGroup pg : ni.getPortgroup())
                        if (pg.getSpec() != null) pgs.add(pg.getSpec().getName());
                    vh.metadata.put("portgroups", String.join(",", pgs));
                }
            }
        } catch (Exception ignored) {}

        // Primary management IP (assume vmk0, else the first vmk, else DNS)
        String primaryIp = null;
        String vmk0 = vh.metadata.get("vmk0");
        if (vmk0 != null && vmk0.contains("=")) primaryIp = vmk0.split("=")[1].split("/")[0];
        if (primaryIp == null)
            for (String net : vh.managementNets) { primaryIp = net.split("/")[0]; break; }
        if (primaryIp == null) {
            try { primaryIp = InetAddress.getByName(hs.getName()).getHostAddress(); }
            catch (Exception ignored) {}
        }
        vh.ip = primaryIp != null ? primaryIp : hs.getName();
        vh.id = "esxi:" + vh.ip;

        // Datastores (name:free/capacity GB)
        try {
            Datastore[] datastores = hs.getDatastores();
            if (datastores != null) {
                List<String> dss = new ArrayList<>();
                for (Datastore ds : datastores) {
                    DatastoreSummary sum = ds.getSummary();
                    long cap = sum != null ? sum.getCapacity() / (1024L*1024*1024) : 0;
                    long free = sum != null ? sum.getFreeSpace() / (1024L*1024*1024) : 0;
                    dss.add(ds.getName() + ":" + free + "/" + cap + "GB");
                }
                if (!dss.isEmpty()) vh.metadata.put("datastores", String.join("; ", dss));
            }
        } catch (Exception ignored) {}

        // Logical networks attached to the host
        try {
            Network[] networks = hs.getNetworks();
            if (networks != null) {
                List<String> nets = new ArrayList<>();
                for (Network n : networks) {
                    nets.add(n.getName());
                }
                if (!nets.isEmpty()) vh.metadata.put("networks", String.join(",", nets));
            }
        } catch (Exception ignored) {}

        return vh;
    }

    // ===================== VM =====================
    private static com.g120s.janus.model.VirtualMachine buildVm(
            com.vmware.vim25.mo.VirtualMachine vmo, Map<String, String> dvPgNames) {
        com.g120s.janus.model.VirtualMachine vm = new com.g120s.janus.model.VirtualMachine();
        vm.name = vmo.getName();

        try {
            if (vmo.getConfig() != null) {
                vm.uuid = vmo.getConfig().getInstanceUuid();
                if (vm.uuid == null) vm.uuid = vmo.getConfig().getUuid();
                vm.guestOs = vmo.getConfig().getGuestFullName();
            }
        } catch (Exception ignored) {}

        try {
            if (vmo.getRuntime() != null && vmo.getRuntime().getPowerState() != null)
                vm.powerState = vmo.getRuntime().getPowerState().toString();
        } catch (Exception ignored) {}

        // Guest IP (if vmtools is running)
        try {
            if (vmo.getGuest() != null) {
                vm.ip = vmo.getGuest().getIpAddress();
                if (vm.ip == null && vmo.getGuest().getNet() != null) {
                    for (GuestNicInfo nic : vmo.getGuest().getNet()) {
                        if (nic.getIpAddress() != null && nic.getIpAddress().length > 0) {
                            vm.ip = nic.getIpAddress()[0];
                            break;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // Virtual ethernet cards
        try {
            if (vmo.getConfig() != null && vmo.getConfig().getHardware() != null
                    && vmo.getConfig().getHardware().getDevice() != null) {
                for (VirtualDevice dev : vmo.getConfig().getHardware().getDevice()) {
                    if (dev instanceof VirtualEthernetCard card) {
                        String mac = card.getMacAddress();
                        if (mac != null && !mac.isEmpty()) mac = mac.toLowerCase();
                        String net = backingName(card, dvPgNames);
                        vm.nics.add((mac == null ? "no-mac" : mac) + "@" + net);
                        if (vm.mac == null && mac != null) vm.mac = mac;
                    }
                }
            }
        } catch (Exception ignored) {}

        return vm;
    }

    private static String backingName(VirtualEthernetCard card, Map<String, String> dvPgNames) {
        VirtualDeviceBackingInfo b = card.getBacking();
        if (b instanceof VirtualEthernetCardNetworkBackingInfo nb)
            return nb.getDeviceName() != null ? nb.getDeviceName() : "stdpg";
        if (b instanceof VirtualEthernetCardDistributedVirtualPortBackingInfo dvb
                && dvb.getPort() != null) {
            String key = dvb.getPort().getPortgroupKey();
            String name = dvPgNames.get(key);
            return name != null ? "dvs:" + name : "dvs-key:" + key;
        }
        if (b instanceof VirtualEthernetCardLegacyNetworkBackingInfo lb)
            return "legacy:" + lb.getDeviceName();
        return "unknown";
    }

    // ===================== helpers =====================
    private static ManagedEntity[] safeArray(ManagedEntity[] arr) {
        return arr != null ? arr : new ManagedEntity[0];
    }

    private static String normalizeUrl(String url) {
        if (url == null || url.isBlank())
            throw new IllegalArgumentException("vCenter/ESXi URL must not be blank");
        if (!url.startsWith("http://") && !url.startsWith("https://"))
            url = "https://" + url;
        if (!url.endsWith("/sdk")) url = url.replaceAll("/+$", "") + "/sdk";
        return url;
    }

    private static int prefixLength(String subnetMask) throws Exception {
        byte[] address = InetAddress.getByName(subnetMask).getAddress();
        int bits = 0;
        for (byte value : address) bits += Integer.bitCount(value & 0xFF);
        return bits;
    }
}