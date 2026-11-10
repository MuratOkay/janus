# Janus User Guide

This guide walks through installing Janus, running discoveries, reading the
report, using the web UI, and tuning the crawl for larger environments.

## 1. Installation

### From source

```bash
git clone <repository-url> janus
cd janus
./mvnw clean package
```

Artifacts:

- `target/janus-0.0.1-SNAPSHOT.jar` — executable, self-contained jar.
- `target/janus-0.0.1-SNAPSHOT.jar.original` — thin jar (library use).

Verify it runs:

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --help || java -jar target/janus-0.0.1-SNAPSHOT.jar
```

Running with no arguments prints the usage text.

### Privileges

- **TCP / ICMP / SNMP / mDNS / SSDP / NetBIOS** — no special privileges needed.
- **ARP scanning and LLDP/CDP capture** — require raw socket access. On Linux run
  with `sudo`, or grant the capability to the JVM:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which java)")"
  ```

  Without raw-socket access Janus still runs; the affected strategies produce a
  warning in the report and are simply skipped.

### Native access and the JNA warning

JNA loads `libpcap` through `System.load`, which the JVM has treated as a
restricted method since JDK 24. Without explicit permission you get this four-line
warning on every run, and JDK releases after 25 are expected to refuse the call
outright rather than warn:

```
WARNING: A restricted method in java.lang.System has been called
WARNING: java.lang.System::load has been called by com.sun.jna.Native ...
```

The packaged jar declares the permission in its manifest
(`Enable-Native-Access: ALL-UNNAMED`), so **`java -jar` needs no extra flag** and
the warning does not appear.

This applies only to a jar launch. If you run from the classpath instead
(`java -cp target/classes:... com.g120s.janus.Main`) there is no manifest to read
and the warning returns; pass the flag yourself:

```bash
java --enable-native-access=ALL-UNNAMED -cp target/classes:... com.g120s.janus.Main
```

The grant is safe to give: Janus is a network scanner that legitimately needs
libpcap for ARP and LLDP/CDP capture. Without the permission Janus still runs, but
those two strategies degrade to the warnings described above — which is also what
happens without `CAP_NET_RAW`.

## 2. Your first discovery

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar \
  --cidr 192.168.1.0/24 \
  --snmp public \
  --out reports/home.json
```

What happens:

1. Janus expands each `--cidr` into host addresses and probes the standard port
   set (SSH, SMB, RDP, WinRM, ESXi, Proxmox, VNC, ...).
2. It pings, and on matching local segments it also does ARP plus mDNS/SSDP/NetBIOS.
3. Reachable hosts are enriched: OUI vendor lookup, SNMP `sysDescr`/`sysName`,
   the router's directly attached networks (`ipAdEntNetMask`) and routing table
   (honouring `ipRouteMask`) plus its ARP table. Newly learned subnets keep their
   real prefix and are queued for crawling.
4. If virtualization credentials were supplied, their management subnets are added
   to the crawl and their VMs are enumerated.
5. VMs are matched to hosts by MAC address, LLDP/CDP is applied to build L2 links,
   and the result is written to `--out`.

The console prints a one-line summary:

```
Done. 42 devices, 7 virtual machines, 2 hosts, 3 network segments, 5 L2 links.
```

## 3. Choosing discovery strategies

All strategies are on by default. Turn off the ones you do not want:

```bash
# Fast, quiet, port-based only:
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --no-icmp --no-arp --no-mdns --no-ssdp --no-netbios --no-lldp --no-snmp --no-dns

# Passive-ish: reuse the SNMP routing table to discover neighbors:
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 --snmp public --no-tcp
```

Notes:

- `--no-tcp` disables port probing, so port-based fingerprints (OS guess,
  virtualization detection) lose most of their signal.
- ARP only runs on segments that exactly match a local interface, because ARP
  does not cross routers.

## 3.1 Host name resolution

Janus resolves each host's name from several independent sources and keeps track
of which source produced which name. If you see devices without a `hostname`,
this is the section to read.

Sources, in precedence order (first non-empty wins for `hostname`):

| Source key | How it works | Requirements |
| --- | --- | --- |
| `ptr` | Reverse DNS (PTR) lookup | Reachable DNS server |
| `snmp` | SNMP `sysName` (1.3.6.1.2.1.1.5.0) | SNMP enabled + community |
| `tls` | HTTPS certificate CN or SAN | TLS on 443/8443/9440 |
| `netbios` | NetBIOS Node Status (UDP/137) | Windows hosts |
| `mdns` | mDNS `.local` host records | Multicast DNS enabled |
| `ssdp` | UPnP `friendlyName` / `SERVER` header | UPnP devices |

Point it at a specific DNS server (useful when the system resolver is not the
same as the network's DNS), and give lookups a budget:

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --dns-server 10.0.0.53 --dns-timeout 1500
```

Disable the name lookups you do not want:

```bash
# No reverse DNS and no TLS certificate probing:
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --no-dns --no-tls-names
```

Each device in the report records **every** name it found and where it came from,
so you can audit a suspicious or generic result:

```json
"hostname": "web01.corp.example.com",
"fqdn": "web01.corp.example.com",
"hostnamesBySource": {
  "mdns": "web01",
  "netbios": "WEB01",
  "ptr": "web01.corp.example.com"
},
"aliases": ["WEB01", "web01", "web01.corp.example.com"]
```

Tips when names are missing:

- Confirm reverse DNS actually works for the range: `dig -x 10.0.0.20`.
- If DNS is fine but Janus sees nothing, check that `--no-dns` was not set and that
  `--dns-server` points at a resolver that can see that zone.
- Devices with no DNS and no SNMP will only ever resolve via NetBIOS/mDNS/SSDP,
  and only if those protocols are enabled on the device.

## 4. Tuning for larger networks

| Flag | Default | When to raise/lower |
| --- | --- | --- |
| `--threads` | 64 | Raise on beefy hosts scanning many subnets; lower if the NIC or target devices are overwhelmed. |
| `--tcp-timeout` | 500 ms | Lower on low-latency LANs, raise over WAN/VPN links. |
| `--snmp-timeout` | 1000 ms | Raise for slow or busy network devices. |
| `--max-subnets` | 64 | Caps total segments crawled (protects against runaway route-table expansion). |
| `--max-depth` | 4 | Maximum hops from a seed. A subnet discovered while crawling depth *n* becomes depth *n+1*; anything past the limit is reported, not silently dropped. |
| `--max-hosts-per-subnet` | 1024 | Caps how many addresses are probed per segment. Raise it to cover a `/16` fully; a truncated segment is reported as a warning. |
| `--sweep-policy` | `full` | What to probe: `full` sweeps the range (capped), `known` probes only addresses SNMP reported, `sample` probes known + a spread of the range. See §4.1. |
| `--sample-hosts-per-subnet` | 32 | Addresses sampled across the range under `--sweep-policy sample`. |
| `--pps` | unlimited | Caps probe starts per second. `--threads` limits concurrency; this limits rate. Lower it to protect weak switches. |
| `--exclude` | none | A range that must never be probed (repeatable). Applies even when a seed or SNMP route encloses it. |
| `--progress` | `auto` | `auto` redraws in place on a terminal and prints plain lines when redirected; `plain` always prints lines; `none` is silent. |
| `--quiet` | off | Same as `--progress none`. Use in scripts and cron jobs. |
| `--verbose` | off | Raises the raw-socket libraries from warnings to info. Useful when a strategy misbehaves. |
| `--lldp-duration` | 45000 ms | Longer captures catch more advertisements on slow networks. |

Example for a /16 split into /24s with a bigger pool:

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar \
  --cidr 10.20.0.0/16 --threads 256 --max-subnets 256 --out reports/dc.json
```

Wide segments are no longer rejected: a `/16` is expanded up to
`--max-hosts-per-subnet` addresses and the run reports exactly how much of it was
covered. Prefixes below `/8` are refused outright. Sweeping a large range host by
host is slow, so prefer letting SNMP-discovered subnets drive the crawl.

### 4.1 Choosing a sweep policy

Sweeping every address of a large range is rarely affordable. A `/16` holds 65534
hosts and each one costs one connect attempt per probe port — roughly a million
attempts for the default port list, plus the SNMP lookups afterwards. Routers and
switches already know which addresses are in use, so asking them is faster and far
gentler on the network.

| Policy | Probes | Best for |
| --- | --- | --- |
| `full` (default) | Every address in the range, capped by `--max-hosts-per-subnet`. | Small or medium segments, and any segment with no SNMP data. The only policy that finds a silent host. |
| `known` | Only addresses reported by SNMP (interface addresses and ARP caches). | Large enterprise ranges where the routers are managed. Fastest and quietest. |
| `sample` | Known addresses, plus the segment gateway, plus `--sample-hosts-per-subnet` addresses spread across the whole range. | A first pass over a big range, or validating that `known` data looks sane. |

```bash
# Crawl a /16 quickly by trusting the routers
java -jar target/janus-0.0.1-SNAPSHOT.jar \
  --cidr 10.20.0.0/16 --sweep-policy known --out reports/dc-known.json

# Known hosts plus a spread of 64 addresses across each range
java -jar target/janus-0.0.1-SNAPSHOT.jar \
  --cidr 10.20.0.0/16 --sweep-policy sample --sample-hosts-per-subnet 64 \
  --out reports/dc-sample.json
```

Two behaviours worth knowing:

- **Sampling is deterministic.** The addresses are derived from the CIDR, so two
  runs over the same segment probe the same hosts and their results are
  comparable. A random sample would make successive scans impossible to diff.
- **`known` on a segment with no SNMP data probes nothing** and says so:
  `segment 10.5.0.0/24: no SNMP host data, so nothing was probed under
  --sweep-policy known (use sample or full)`. Admitting the gap is better than
  reporting an empty network as if nothing were there.

`--pps` is a separate limit from `--threads`. `--threads` bounds how many probes
are in flight; `--pps` bounds how many *start* per second. 256 threads can still
hammer a weak switch if every connect returns instantly, so pace with `--pps` when
protecting fragile network hardware.

## 5. Watching a scan run

A scan reports what it is doing while it runs, so a long crawl is not a silent
black box:

```
Janus network discovery
  seeds    : 192.168.1.0/24
  policy   : full (cap 1024/segment)   threads: 128   pps: unlimited
  enabled  : tcp icmp arp mdns snmp lldp dns tls
[00:00:00] 2 segment(s) queued from local interfaces and routes
[00:00:00] crawling 192.168.1.0/24  (segment 1 of >=2, queue 1)  254 target(s)
[00:00:03]   192.168.1.0/24  tcp 138/254  2 device(s)
[00:00:06]   192.168.1.0/24  icmp 247/254  3 device(s)
[00:00:32] done 192.168.1.0/24  3 device(s)  (31.8s)
```

Things worth knowing about this output:

- **`of >=2`** — the number of subnets is not known when the crawl starts, because
  new ones are discovered as routers report their interfaces and routes. The figure
  is a lower bound that grows, not a fixed total that suddenly proves wrong.
- **`tcp` and `icmp` are named** — they are two separate sweeps of the same range,
  so their counters restart by design.
- **One line is redrawn in place** on a terminal. When output is redirected to a
  file the same events become plain lines, because a carriage return would
  overwrite text inside the log instead of on screen.
- **Updates are throttled** to about four per second; a `/16` is over a million
  probes and reporting each one would cost more than the scan.

Progress goes to stdout and is independent of the report file, so you can watch a
scan and still capture the JSON.

### Why virtual threads and `--threads`

Probes run on virtual threads, with `--threads` as the cap on probes in flight.
Blocking socket I/O parks a virtual thread cheaply, so the limit is there to protect
the network and the local port range rather than to save memory. Raising
`--threads` genuinely increases throughput; `--pps` remains the separate limit on
probe *rate*.

## 6. Virtualization inventory

### VMware ESXi and vCenter

```bash
# Direct ESXi host
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --esxi 10.0.0.10,root,secret --out reports/esxi.json

# vCenter (insecure TLS for self-signed certs)
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --vcenter 10.0.0.5 --vcenter-user administrator@vsphere.local \
  --vcenter-pass secret --vcenter-insecure --out reports/vc.json
```

### Proxmox

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --proxmox 10.0.0.20,8006,root@pam,secret --out reports/proxmox.json
```

### KVM / libvirt

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --kvm 10.0.0.30,root,secret --out reports/kvm.json

# or an explicit libvirt URI
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --libvirt qemu+ssh://root@10.0.0.30/system
```

### Microsoft Hyper-V

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --cidr 10.0.0.0/24 \
  --hyperv 10.0.0.40 --hyperv-user Administrator --hyperv-pass secret \
  --hyperv-domain CONTOSO --hyperv-https --out reports/hyperv.json
```

When credentials are provided, the corresponding management subnets are added to
the crawl and their VMs are enumerated over the API, then deduplicated against
fingerprint-only results.

## 7. Reading the report

Every run writes a single JSON document (pretty-printed). A trimmed device entry:

```json
{
  "ip": "192.168.1.20",
  "mac": "00:0c:29:aa:bb:cc",
  "hostname": "web-01",
  "vendor": "vmware",
  "kind": "VIRTUAL_MACHINE",
  "openPorts": [22, 80, 443],
  "services": [],
  "discoveredBy": ["arp", "tcp", "snmp"],
  "osGuess": "linux",
  "virtualizationType": "vmware",
  "ownerHostId": "esxi:192.168.1.10",
  "metadata": { "sysDescr": "Linux web-01 6.1.0" }
}
```

Field reference:

- **kind** — `WORKSTATION`, `SERVER`, `ROUTER`, `SWITCH`, `FIREWALL`, `PRINTER`,
  `IOT`, `MOBILE`, `STORAGE`, `VIRTUALIZATION_HOST`, `VIRTUAL_MACHINE`, `UNKNOWN`.
- **hostname** — the best name found, chosen by source precedence (see §3.1).
- **aliases** — every distinct name found for the host, from all sources.
- **fqdn** — the first fully-qualified name found (contains a dot), or `null`.
- **hostnamesBySource** — map of resolver key (`ptr`, `snmp`, `tls`, `netbios`,
  `mdns`, `ssdp`) to the name it produced, for auditing.
- **vendor** — resolved from the MAC OUI (e.g. `vmware`, `dell`, `cisco`).
- **osGuess** — one of `windows`, `linux`, `macos`, `ios`, `junos`, `freebsd`,
  `esxi`, `printer-firmware`, or `null` when there is not enough signal.
- **virtualizationType** — `esxi`, `vcenter`, `proxmox`, `kvm`, `hyperv`, `xen`,
  `nutanix`, `virtualbox`.
- **discoveredBy** — every strategy that observed the host (`arp`, `tcp`, `icmp`,
  `snmp`, `mdns`, `ssdp`, `netbios`, `snmp-arp`, ...).
- **metadata** — free-form; `sysDescr` holds the raw SNMP banner.

Top-level `vhosts`, `vms`, `links`, `segments`, and `warnings` mirror the CLI
summary and let consumers render topology or triage partial failures.

### 7.2 `segments` — the discovered subnet inventory

Each segment records where it came from and how completely it was examined:

```json
{
  "cidr": "10.0.5.0/24",
  "gateway": "10.0.0.1",
  "parentCidr": "10.0.0.0/16",
  "depth": 1,
  "coveredBy": null,
  "hostsProbed": 254,
  "hostsTotal": 254,
  "sweepPolicy": "full",
  "discoveredBy": ["snmp-route@10.0.0.1"]
}
```

- **cidr** — always canonical (`10.0.5.0/24`, never `10.0.5.7/24`).
- **parentCidr / depth** — the segment this one was learned from and its distance
  in hops from a seed. Seeds have `depth: 0` and `parentCidr: null`.
- **gateway** — the next hop for a routed subnet, or the router interface address
  for a directly attached one. `null` for seeds taken from a local interface.
- **hostsProbed / hostsTotal** — how many of the range's usable addresses were
  actually probed versus how many exist. `hostsProbed < hostsTotal` means the
  sweep was capped by `--max-hosts-per-subnet` or deliberately reduced by
  `--sweep-policy`; a warning says the same.
- **sweepPolicy** — `full`, `known` or `sample`, recording how the range was
  probed so a sparse result can be told apart from a small network.
- **coveredBy** — set when the range was already swept as part of a wider,
  fully scanned network, so it was recorded but deliberately not re-scanned.
- **discoveredBy** — provenance: `seed`, `local-interface`, `local-route`,
  `snmp-if@<router>`, `snmp-route@<router>`, `lldp-mgmt`, `vm-management@<host>`.
  A `…-mask-assumed` suffix marks a prefix that had to be guessed because the
  source reported no netmask.
- **description** — the switch interface label (`ifAlias`, falling back to
  `ifName`) for subnets learned from a router's attached interfaces, e.g.
  `uplink-to-core`.
- **vlan** — populated only when a source states it; host-level VLAN membership is
  recorded on the device instead (see §6.3).

### 7.3 Layer-2 and VLAN metadata on devices

When a switch or router exposes its forwarding tables, each host gains:

- `l2.switch` — the IP of the switch that reported the port.
- `l2.bridgePort` / `l2.portName` — the bridge port number and its interface name,
  e.g. `12` and `Gi1/0/12`.
- `vlan.<id>` — the bridge port the host reaches on that VLAN, and
  `vlan.<id>.name` when the switch names the VLAN.

Sources: `dot1dTpFdbPort` + `dot1dBasePortIfIndex` for the VLAN-agnostic port,
`dot1qTpFdbPort` (indexed by VLAN + MAC) for per-VLAN placement, and
`dot1qVlanStaticName` for VLAN names. The web UI reads any `vlan.` key to colour
and group by VLAN, so no separate field is needed.

## 8. Using the web UI

```bash
java -jar target/janus-0.0.1-SNAPSHOT.jar --web --server.port=8080 \
  --janus.report.path=reports/home.json
# open http://localhost:8080
```

The UI renders a d3 force-directed topology from the report and lets you switch
layouts, colors, search hosts, and inspect a device detail panel.

The **Subnets** panel lists every discovered network as a tree built from
`parentCidr`/`depth`, each row showing its coverage (`probed/total`), the sweep
policy used, how many devices fell inside it, the interface description when one
is known, and a `covered by` flag when the range was skipped because a wider
network had already been swept completely. A range that was only partly probed
therefore reads as `0/65534 probed`, not as an empty network.

REST endpoints (all GET):

| Endpoint | Purpose |
| --- | --- |
| `/api/health` | Liveness: `{"status":"up","time":"..."}`. |
| `/api/report` | Full `DiscoveryResult` for the latest (or `?name=` a specific) report. |
| `/api/reports` | List of available report files. |
| `/api/summary` | Counts: devices, vhosts, vms, segments, links, by kind, by protocol, duration. |

Point it at a different report or directory with
`--janus.report.path=FILE` or `--janus.report.dir=DIR`.

## 9. Troubleshooting

- **No devices at all.** Confirm the CIDR is reachable, or that the range was not
  reduced by `--sweep-policy known` without SNMP data. Try disabling raw-socket
  strategies to isolate, then re-enable with privileges.
- **ARP / LLDP warnings.** Expected without `CAP_NET_RAW`. Grant the capability or
  run with `sudo`.
- **SNMP shows nothing.** Verify the community and that UDP/161 reaches the device.
  Check `warnings` in the JSON for `snmp@<ip>: ...` entries.
- **Hostnames are missing.** Work through §3.1: confirm reverse DNS resolves the
  range (`dig -x <ip>`), that `--no-dns` is not set, and that `--dns-server` points
  at a resolver that can see that zone. Devices without DNS or SNMP fall back to
  NetBIOS/mDNS/SSDP only. Inspect `hostnamesBySource` on the device to see which
  resolvers ran.
- **Web UI is empty.** Ensure a report file exists at the configured path and that
  `/api/health` responds; the UI loads `/api/report` on startup.
- **Port probing is slow.** Lower `--tcp-timeout`; raise `--threads`.

## 10. Safety and legal

Scan only networks you own or are explicitly authorized to test. Port probing,
ARP sweeps, and authenticated virtualization APIs can trigger IDS/IPS alarms and
may be regulated in your environment.
