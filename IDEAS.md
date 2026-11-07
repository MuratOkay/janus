Neden bu yöntem seti?

| Yöntem | Ne zaman işe yarar |
|---|---|
| **TCP connect** (22/80/443/445/3389/5985/8006...) | ICMP firewall'da bloklu olsa bile port açık her host'u yakalar. **Ana canlılık sinyali.** |
| **ARP** (pcap4j) | Aynı L2 segmentte %100 doğruluk — sadece paket gitmesi yeter. |
| **mDNS / SSDP / NetBIOS** | UDP multicast; çoğu yerde engellenmez; hostname/servis bilgisi verir. |
| **SNMP (v1/v2c/v3)** | Router/switch'ten route ve ARP tabloları → **başka LAN'lar** ve MAC envanteri. |
| **LLDP/CDP** (pcap) | Switch/router komşuları, VLAN ve yönetim IP'leri → topoloji ve ek segmentler. |
| **Sanallaştırma API'leri** | VMware/Proxmox/KVM/Hyper-V → kesin VM↔host eşlemesi. |
| **MAC OUI + L2 heuristic** | API yoksa "muhtemel sanal makine" tespiti ve çoğu zaman doğru host eşleşmesi. |

**Çoklu LAN zincirleme:** Yeni segmentler 4 kaynaktan keşfedilir → BFS kuyruğuna eklenir:  
1. Yerel arayüz CIDR'leri,  
2. SNMP routing table (default olmayan),  
3. LLDP komşularının yönetim IP'leri,  
4. Sanallaştırma host'unun VMkernel/bridge ağları.

**Kritik noktalar / üretim için tavsiyeler:**

- **ARP/LLDP** için `run as root` / `CAP_NET_RAW` veya Windows'ta **npcap**. Aksi halde yalnızca TCP+UDP keşifleri çalışır.
- **ESXi/KVM/Hyper-V'nin SSH/WinRM'i kapalıysa** API katmanı atlanır; yalnızca OUI + port fingerprint ile "sanal makine" işaretlenir, eşleşme `api-mac` yerine `heuristic-l2-oui` olur. Kesin eşleme için ilgili SDK'yı (yavijava / libvirt-java / WinRM4j) `pom.xml`'e ekle ve `VirtualizationDiscovery` sınıfını genişlet.
- **Rate limiting:** Thread pool'u ve timeout'ları çok agresif yapma; SNMP cihazları aşırı sorgudan düşer. `--threads 256` ile 10.0.0.0/16'yı taramak yavaş ama güvenli.
- **OUI tablosu:** `IEEE oui.csv`'yi indirip `Map<String,String>` olarak yükle; küçük dosyada `VirtualizationDetector.vmVendorByMac` içine ekle.
- **Dağıtık çalışma:** Büyük ağlarda seg mentor başına küçük bir agent (aynı jar `--agent-mode`) çalıştırıp sonuçları merge etmek gerekir.
- **Kimlik doğrulama:** Üretimde SSH `HostKeyVerifier`'ı gerçek anahtar dosyasıyla değiştir, Proxmox için self-signed TLS'i kaldırma (truststore).
- **Yasal:** Sadece yetkili olduğun ağlarda çalıştır.
