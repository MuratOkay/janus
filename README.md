# Janus

Janus is a network discovery and virtualization inventory tool for Java. It
sweeps one or more IPv4 subnets, fingerprints the hosts it finds, maps
virtualization hosts and their virtual machines, and produces a single JSON
report that can be explored through a built-in web UI.

- Multi-strategy host discovery: TCP probes, ICMP echo, ARP, mDNS, SSDP, NetBIOS.
- Multi-source host name resolution: reverse DNS (PTR), SNMP `sysName`, TLS
  certificate CN/SAN, NetBIOS, mDNS and SSDP — with per-source provenance.
- Service and system enrichment over SNMP v2c (`sysDescr`, `sysName`, routing
  and ARP tables that feed new segments back into the crawl).
- OS fingerprinting from SNMP banners, open ports, hostnames and MAC OUI data.
- Virtualization detection through fingerprints and authenticated APIs:
  VMware ESXi, vCenter, Proxmox, KVM/libvirt, Microsoft Hyper-V, Xen, Nutanix.
- VM-to-host matching by MAC address.
- L2 topology from LLDP/CDP frames captured on local interfaces.
- Console and web output backed by one JSON model.

> **Use Janus only on networks you are authorized to scan.**

## Requirements

- Java 25 (the build targets `java.version=25`).
- Maven 3.9+ or the bundled `./mvnw`.
- Raw-socket access (root / `CAP_NET_RAW`) for ARP and LLDP/CDP capture. Other
  discovery strategies run without elevated privileges.

## Build

```bash
./mvnw clean package
```

The runnable, self-contained jar is produced at
`target/janus-0.0.1-SNAPSHOT.jar`.

## Quick start

Run a discovery against a subnet and write a JSON report:

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 192.168.1.0/24 --out report.json
```

Launch the web UI (reads the report and serves a topology view):

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --web --server.port=8080
# open http://localhost:8080
```

## CLI overview

| Option | Description |
| --- | --- |
| `--cidr CIDR` | Seed network, repeatable. Defaults to the host's local networks. |
| `--snmp COMMUNITY` | SNMP v2c community, repeatable (default `public`). |
| `--no-tcp` `--no-icmp` `--no-arp` `--no-mdns` `--no-ssdp` `--no-netbios` `--no-snmp` `--no-lldp` `--no-dns` `--no-tls-names` | Disable individual strategies. |
| `--dns-server IP` | DNS server for PTR lookups (default: system resolver). |
| `--dns-timeout MS` | Reverse-DNS and TLS-name lookup timeout. |
| `--threads N` | Worker pool size (default 64). |
| `--tcp-timeout MS` / `--snmp-timeout MS` | Per-probe timeouts. |
| `--max-subnets N` / `--max-depth N` | Crawl limits. |
| `--lldp-duration MS` | How long to capture LLDP/CDP frames. |
| `--out FILE` | Output JSON path (default `discovery-report.json`). |
| `--esxi HOST,USER,PASS` | ESXi credential (repeatable). |
| `--proxmox HOST,PORT,USER,PASS` | Proxmox credential. |
| `--kvm HOST,USER,PASS` | KVM/libvirt credential. |
| `--hyperv HOST --hyperv-user U --hyperv-pass P [--hyperv-domain D] [--hyperv-port N] [--hyperv-https]` | Hyper-V over WinRM. |
| `--vcenter URL --vcenter-user U --vcenter-pass P [--vcenter-insecure]` | vCenter API. |
| `--libvirt URI [--libvirt-user U] [--libvirt-pass P]` | libvirt URI. |
| `--web [--server.port=8080] [--janus.report.path=FILE]` | Start the web UI. |

See [USER_GUIDE.md](USER_GUIDE.md) for full, worked examples and
[ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Output

`DiscoveryResult` serializes to JSON with these top-level fields:

- `segments` — discovered network segments with their discovery source.
- `devices` — hosts with IP, MAC, `hostname`, `aliases`, `fqdn`,
  `hostnamesBySource` (provenance per resolver), vendor, kind, open ports,
  services, `osGuess`, `virtualizationType`, and free-form `metadata`.
- `vhosts` — virtualization hosts and the VM MAC ranges they manage.
- `vms` — virtual machines, matched to a host and (when possible) an IP.
- `links` — L2 adjacency from LLDP/CDP.
- `warnings` — non-fatal errors collected during the run.
- `startedAt` / `finishedAt` — epoch milliseconds.

## License

MIT. See [LICENSE](LICENSE).
