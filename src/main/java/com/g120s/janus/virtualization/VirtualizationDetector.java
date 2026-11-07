package com.g120s.janus.virtualization;

import com.g120s.janus.model.Device;
import java.util.Map;
import java.util.Set;

public final class VirtualizationDetector {

    /**
     * Yaygın donanım/OS üreticileri için OUI tablosu.
     * MAC'in ilk 3 baytı (XX:XX:XX) ile eşleşir.
     */
    private static final Map<String, String> OUI_VENDORS = Map.ofEntries(
            // Sanallaştırma platformları
            Map.entry("00:0c:29", "vmware"),
            Map.entry("00:50:56", "vmware"),
            Map.entry("00:05:69", "vmware"),
            Map.entry("00:1c:14", "vmware"),
            Map.entry("00:15:5d", "microsoft"),
            Map.entry("00:1d:d8", "microsoft"),
            Map.entry("00:03:ff", "microsoft"),
            Map.entry("00:16:3e", "xen"),
            Map.entry("52:54:00", "qemu-kvm"),
            Map.entry("50:6b:8d", "nutanix"),
            Map.entry("08:00:27", "virtualbox"),
            Map.entry("0a:00:27", "virtualbox"),
            // Sunucu donanımı
            Map.entry("00:14:4f", "oracle"),
            Map.entry("00:1b:21", "intel"),
            Map.entry("00:1e:67", "intel"),
            Map.entry("00:25:90", "supermicro"),
            Map.entry("3c:ec:ef", "supermicro"),
            Map.entry("ac:1f:6b", "supermicro"),
            Map.entry("00:21:9b", "dell"),
            Map.entry("00:1e:c9", "dell"),
            Map.entry("14:fe:b5", "dell"),
            Map.entry("b0:83:fe", "dell"),
            Map.entry("00:1f:29", "hp"),
            Map.entry("00:25:b5", "hp"),
            Map.entry("3c:d9:2b", "hp"),
            Map.entry("94:57:a5", "hp"),
            Map.entry("00:0a:f7", "broadcom"),
            Map.entry("00:1b:44", "citrix"),
            Map.entry("00:1b:78", "citrix"),
            // Ağ donanımı
            Map.entry("00:1b:17", "cisco"),
            Map.entry("00:1e:13", "cisco"),
            Map.entry("00:26:0b", "cisco"),
            Map.entry("00:24:97", "juniper"),
            Map.entry("00:23:9c", "juniper"),
            Map.entry("00:1a:1e", "aruba"),
            Map.entry("00:0c:42", "mikrotik"),
            Map.entry("48:8f:5a", "mikrotik"),
            Map.entry("00:24:a5", "ubiquiti")
    );

    /** Açık portlar + banner + OUI'ye bakarak host tipini tahmin eder. */
    public static String guessType(Device d) {
        Set<Integer> p = d.openPorts;
        if (p.contains(902) || (p.contains(443) && p.contains(427) && p.contains(80)))
            return "esxi";
        if (p.contains(9443) && p.contains(443)) return "vcenter";
        if (p.contains(8006))                    return "proxmox";
        if (p.contains(16509) || p.contains(16514)) return "kvm";
        if (p.contains(5985) || p.contains(5986))
            return looksLikeWindows(d) ? "hyperv" : null;
        if (p.contains(9440))                    return "nutanix";
        if (p.contains(443) && "xen".equals(vendorOUI(d))) return "xen";
        return null;
    }

    /**
     * WinRM açık bir cihazın gerçekten Windows host olup olmadığını doğrular.
     * Sadece port sayısına bakmak, WinRM açık bir iş istasyonunu yanlışlıkla
     * sanallaştırma host'u saymaya yol açıyordu.
     */
    public static boolean looksLikeWindows(Device d) {
        String vendor = vendorOUI(d);
        if (vendor.contains("microsoft")) return true;
        String descr = String.valueOf(d.metadata.getOrDefault("sysDescr", "")).toLowerCase();
        if (descr.contains("windows") || descr.contains("hyper-v")) return true;
        Set<Integer> p = d.openPorts;
        // Windows'a özgü port kombinasyonları (RDP / SMB + RPC)
        return p.contains(3389) || (p.contains(445) && p.contains(135));
    }

    /** MAC adresindeki OUI'yi üretici/tip adına çevirir; bilinmiyorsa "". */
    public static String vendorOUI(Device d) {
        return vendorByOuiPrefix(d.mac);
    }

    /** OUI ön ekinden üretici adı (küçük harf) döndürür. */
    public static String vendorByOuiPrefix(String mac) {
        String prefix = ouiPrefix(mac);
        return prefix == null ? "" : OUI_VENDORS.getOrDefault(prefix, "");
    }

    /** MAC adresinden "aa:bb:cc" biçiminde normalize edilmiş OUI ön eki. */
    public static String ouiPrefix(String mac) {
        if (mac == null) return null;
        // Ayraç farkı (aa-bb-cc / aa:bb:cc / aabb.ccdd.eeff) normalize edilmeli
        String normalized = mac.trim().toLowerCase().replace('-', ':');
        if (normalized.length() < 8) return null;
        return normalized.substring(0, 8);
    }

    /** Sanal makine MAC OUI aralıkları. */
    public static String vmVendorByMac(String mac) {
        String pref = ouiPrefix(mac);
        if (pref == null) return null;
        return switch (pref) {
            case "00:0c:29", "00:50:56", "00:05:69", "00:1c:14" -> "vmware";
            case "00:15:5d", "00:1d:d8", "00:03:ff" -> "hyperv";
            case "00:16:3e" -> "xen";
            case "52:54:00" -> "qemu-kvm";
            case "08:00:27" -> "virtualbox";
            case "0a:00:27" -> "virtualbox-nat";
            case "50:6b:8d" -> "nutanix";
            default -> null;
        };
    }

    /** Cihaz bir sanal makine mi? */
    public static boolean isVirtualMachineMac(String mac) {
        return vmVendorByMac(mac) != null;
    }
}
