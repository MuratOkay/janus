package com.g120s.janus.discovery;

import com.g120s.janus.model.Device;

import java.util.Locale;
import java.util.Set;

/**
 * Elde edilen zayıf sinyalleri (SNMP sysDescr, açık portlar, hostname, OUI
 * üreticisi) birleştirerek bir işletim sistemi tahmini üretir.
 *
 * <p>Amaç kesin tespit değil, en olası sınıflandırmadır. Sinyaller
 * güvenilirlik sırasına göre değerlendirilir:
 * <ol>
 *   <li>SNMP sysDescr metni (en güçlü sinyal)</li>
 *   <li>Belirgin port parmak izleri (RDP, SSH, SMB/RPC, AFP, IPP...)</li>
 *   <li>Üretici/OUI (Apple → macOS, Microsoft → Windows...)</li>
 *   <li>Hostname kalıpları</li>
 * </ol>
 */
public final class OsFingerprint {

    private OsFingerprint() {}

    /** Bilinen OS sınıfları (küçük harf, kararlı kimlikler). */
    public static final String WINDOWS = "windows";
    public static final String LINUX   = "linux";
    public static final String MACOS   = "macos";
    public static final String IOS     = "ios";     // Cisco IOS
    public static final String JUNOS   = "junos";
    public static final String ANDROID = "android";
    public static final String FREEBSD = "freebsd";
    public static final String ESXI    = "esxi";
    public static final String PRINTER = "printer-firmware";

    /**
     * Cihaz için OS tahmini döndürür; hiçbir sinyal yoksa {@code null}.
     */
    public static String guess(Device d) {
        if (d == null) return null;

        String byDescr = fromSysDescr(d.metadata.get("sysDescr"));
        if (byDescr != null) return byDescr;

        String byVendor = fromVendorAndPorts(d);
        if (byVendor != null) return byVendor;

        String byHost = fromHostname(d.hostname);
        if (byHost != null) return byHost;

        return null;
    }

    /** SNMP sysDescr metninden OS çıkarımı. */
    static String fromSysDescr(String sysDescr) {
        if (sysDescr == null || sysDescr.isBlank()) return null;
        String s = sysDescr.toLowerCase(Locale.ROOT);

        // Ağ işletim sistemleri (IOS/JunOS, Linux'tan önce kontrol edilmeli)
        if (s.contains("cisco ios") || s.contains("ios software")
                || s.contains("ios xe") || s.contains("ios-xe")) return IOS;
        if (s.contains("junos")) return JUNOS;

        // Windows ailesi
        if (s.contains("windows nt") || s.contains("windows server")
                || s.contains("windows 10") || s.contains("windows 11")
                || s.contains("microsoft windows")) return WINDOWS;

        // VMware ESXi
        if (s.contains("vmware esxi") || s.contains("esxi")) return ESXI;

        // macOS / Darwin
        if (s.contains("darwin") || s.contains("mac os")) return MACOS;

        // FreeBSD / pfSense / OPNsense
        if (s.contains("freebsd") || s.contains("pfsense") || s.contains("opnsense"))
            return FREEBSD;

        // Linux dağıtımları (genel)
        if (s.contains("linux")) return LINUX;

        return null;
    }

    /** OUI üreticisi + açık portlara göre çıkarım. */
    static String fromVendorAndPorts(Device d) {
        Set<Integer> p = d.openPorts;
        String vendor = d.vendor == null ? "" : d.vendor.toLowerCase(Locale.ROOT);

        // Yazıcı: IPP / RAW / LPD + yazıcı OUI'leri
        if (p.contains(9100) || p.contains(515)
                || (p.contains(631) && p.contains(80))) {
            if (vendor.contains("hp") || vendor.contains("canon")
                    || vendor.contains("epson") || vendor.contains("brother")
                    || p.contains(9100)) return PRINTER;
        }

        // Apple donanımı → macOS (sunucu portları) veya iOS (mobil)
        if (vendor.contains("apple")) {
            if (p.contains(548) || p.contains(22) || p.contains(88)) return MACOS;
            return null; // iOS/mobil ayrımını port ile yapamayız
        }

        // Windows'a özgü kombinasyonlar
        if (p.contains(3389)) return WINDOWS;
        if (p.contains(5985) || p.contains(5986)) {
            if (vendor.contains("microsoft") || p.contains(445) || p.contains(135))
                return WINDOWS;
        }
        if (p.contains(445) && p.contains(135)) return WINDOWS;

        // VMware ESXi port imzası
        if (p.contains(902) && p.contains(443)) return ESXI;

        // SSH açık Unix-benzeri (Windows vendor değilse)
        if (p.contains(22) && !vendor.contains("microsoft")) return LINUX;

        return null;
    }

    /** Hostname kalıplarından kaba çıkarım. */
    static String fromHostname(String hostname) {
        if (hostname == null || hostname.isBlank()) return null;
        String h = hostname.toLowerCase(Locale.ROOT);

        if (h.contains("esxi") || h.contains("vsphere")) return ESXI;
        if (h.contains("ios-router") || h.contains("ios-switch")) return IOS;

        return null;
    }
}
