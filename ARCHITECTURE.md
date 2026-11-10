# Janus Architecture

Janus is a small, layered Java application. Discovery is orchestrated by a
single class that drives pluggable scanners, fills a plain-Java model, and
hands the model to either the CLI serializer or the Spring web layer.

## 1. High-level flow

```
                 +-----------------------+
   CLI args ---> | DiscoveryConfig       |  (parse + validate)
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 | DiscoveryOrchestrator |  BFS over segments
                 +-----------+-----------+
                             |
        +--------------------+---------------------+
        |                    |                     |
        v                    v                     v
  Host discovery       Enrichment           Virtualization APIs
  (HostScanners,       (SnmpScanner,        (Esxi/VCenter/Proxmox/
   L2Scanner,           OsFingerprint,       Kvm/Libvirt/HyperV)
   MulticastScanners)   Virtualization-
                        Detector)
        |                    |                     |
        +--------------------+---------------------+
                             |
                             v
                 +-----------------------+
                 | DiscoveryResult model |  (plain POJOs)
                 +-----------+-----------+
                             |
                 +-----------+-----------+
                 |                       |
                 v                       v
          Main (Jackson)          ReportController/Service
          -> JSON file            -> REST + web UI
```

## 2. Packages

| Package | Responsibility |
| --- | --- |
| `com.g120s.janus` | Entry point (`Main`), Spring Boot app (`JanusApplication`), Jackson wiring (`JacksonConfig`). |
| `com.g120s.janus.discovery` | Scanning strategies, SNMP, configuration parsing, OS fingerprinting, the orchestrator. |
| `com.g120s.janus.virtualization` | Fingerprint-based detection, authenticated hypervisor APIs, VM-to-host matching. |
| `com.g120s.janus.l2` | Raw-frame LLDP/CDP capture and parsing, topology link construction. |
| `com.g120s.janus.model` | Serializable data model shared by CLI and web. |
| `com.g120s.janus.web` | Spring MVC controller and report-loading service. |

## 3. Configuration

`DiscoveryConfig` is a plain class built by `DiscoveryConfig.fromArgs`. It:

- Holds all tunables (timeouts, limits, enabled strategies) and parsed
  `Credential` objects for hypervisor APIs.
- Validates CIDRs, positive integers, and required credential fields, throwing
  `IllegalArgumentException` with actionable messages.
- Normalizes repeated `--snmp` flags so the default `public` community is dropped
  only once.

`Credential` is a small mutable class (not a record) so follow-up flags like
`--hyperv-user` / `--vcenter-pass` can attach to the most recent host credential.

## 4. Orchestration

`DiscoveryOrchestrator.run()` is a breadth-first crawl:

1. **Seeds.** Uses `--cidr` values; otherwise every network the host can reach,
   which is its local IPv4 interfaces (`localCidrs`) *plus* its own routing table
   (`LocalRoutes`, parsed from `/proc/net/route`). The route table matters because
   a static route to another LAN segment, or a bridge interface that is down but
   still routed, is a subnet no interface enumeration reports.
2. **BFS loop.** For each unvisited segment (bounded by `maxSubnets` and
   `maxDepth`) `crawlSegment` runs the discovery for that one network:
   - `discoverHosts` runs the enabled host-discovery strategies.
   - `enrich` is called for each device found in that segment.

   A failing segment is recorded as a warning and the crawl continues; one
   unparseable or unreachable network must never abort the whole run. Every
   candidate subnet passes through `enqueue`, which canonicalizes the CIDR,
   drops duplicates and refuses oversized ranges (`Cidr.MIN_PREFIX`), so segments
   learned from SNMP, LLDP and hypervisor APIs are all directly comparable.
   Very large segments are expanded only up to `maxHostsPerSubnet` addresses and
   the shortfall is reported instead of silently under-reporting a network.

   **Depth is measured in hops, not network count.** A seed has `depth = 0` and
   every subnet learned while crawling a segment gets `parentCidr` set and
   `depth = parent.depth + 1`. `--max-depth` therefore limits how far from the
   seed the crawl may wander, and a network beyond that limit is reported rather
   than silently dropped.

   **Containment suppression.** When a segment is dequeued, `coveringSegment`
   looks for an already swept network that fully encloses it. If one exists the
   segment is recorded with `coveredBy` set and is *not* swept again — the host
   inventory cannot gain anything from it, but the subnet inventory stays
   complete. Only segments whose sweep ran to completion count, judged by
   `fullyScanned` (`hostsProbed >= hostsTotal`). A truncated sweep leaves part of
   its range unexamined, so it never stands in for a narrower network.
3. **Hypervisor APIs.** Each `Credential` is dispatched to the matching
   discovery class; management subnets reported by hypervisors are pushed back
   onto the frontier so they get crawled too.
4. **LLDP/CDP.** Frames captured at startup are collected, applied via
   `TopologyBuilder`, and management subnets found in advertisements are crawled.
5. **Deduplicate + match.** `deduplicateVirtualization` prefers API-sourced hosts
   over fingerprints; `VMHostMatcher.match` links VMs to hosts by MAC.

The thread pool (`Executors.newFixedThreadPool`) is sized from `--threads` and
shared by TCP probing and LLDP capture.

### Host discovery strategies

`discoverHosts` merges results into a `Map<String, Device>` keyed by IP so that
multiple strategies enrich the same device:

- **TCP** (`HostScanners.tcpScan`) — parallel connect probes over `probePorts`.
- **ICMP** (`HostScanners.icmp`) — echo request.
- **mDNS / SSDP / NetBIOS** (`MulticastScanners`) — multicast and name service.
- **ARP** (`L2Scanner.arpScan`) — raw-socket ARP, only on the matching local
  segment.

Both TCP and ICMP probe the *target list* chosen by `hostsToProbe`, not the whole
segment. That list depends on `SweepPolicy` (`discovery/SweepPolicy.java`):

- `FULL` — `expand` the range up to `maxHostsPerSubnet`, warning when truncated.
- `KNOWN` — only addresses in `CrawlState.knownHosts`, harvested by `collectKnown`
  from SNMP interface and ARP tables. An empty set is reported, never silently
  treated as an empty network.
- `SAMPLE` — the known addresses plus the segment gateway plus
  `sampleHostsPerSubnet` addresses drawn deterministically across the whole range
  (seeded from the CIDR so repeat scans stay comparable).

This matters because sweeping is the dominant cost: a /16 is 65534 hosts times the
number of probe ports. Letting managed routers supply the target list is what makes
large ranges tractable. `RateLimiter` is a separate, optional bound on probe
*starts* per second (`--pps`), distinct from the thread pool's bound on probes in
flight.

### Enrichment

`enrich` fills a device from the strongest signals available:

1. **OUI vendor** — `VirtualizationDetector.vendorByOuiPrefix` maps the MAC prefix.
2. **Virtualization-host hint** — well-known ports (902, 8006, 16509, 9440).
3. **Reverse DNS** — `NameResolver.reverseDns` records a `ptr` name.
4. **SNMP** (`SnmpScanner.query`, tried community by community until one works)
   — records `sysName` as the `snmp` name, sets `sysDescr`, infers
   `ROUTER`/`SWITCH`, queues new segments from the interface table and the routing
   table, and harvests the ARP table into peer devices. Prefixes come from
   `ipAdEntNetMask` (`1.3.6.1.2.1.4.20.1.3`) and `ipRouteMask`
   (`1.3.6.1.2.1.4.21.1.11`); rows are paired by table index, not by column
   position, and `ipRouteType invalid(2)` rows are skipped. Only when a device
   reports no mask at all is a `/24` assumed, and that segment is then tagged
   `…-mask-assumed` so the guess stays visible in the report.
5. **Virtualization fingerprint** — `VirtualizationDetector.guessType`; on a hit,
   a `VirtualizationHost` is registered and the device marked accordingly.
6. **VM detection** — known VM MAC ranges mark the device `VIRTUAL_MACHINE`.
7. **OS guess** — `OsFingerprint.guess` derives `osGuess` from `sysDescr`, open
   ports, hostname and vendor.
8. **TLS name** — if no `ptr`/`snmp` name was found and an HTTPS port is open,
   the certificate CN/SAN becomes the `tls` name.

## 4.1 Host name resolution

`NameResolver` is the single place that decides a device's `hostname`. Every
resolver records what it found through `NameResolver.record(device, source, name)`,
which:

- normalizes the name (trim, collapse whitespace, drop trailing dot, reject IP
  literals and 253+ character strings),
- stores it in `hostnamesBySource[source]`,
- adds it to `aliases`,
- sets `fqdn` on the first name containing a dot,
- calls `pickBest`, which picks the name with the lowest priority number and
  writes it to `hostname`.

Priority (lower wins): `ptr` (10) → `snmp` (20) → `tls` (30) → `netbios` (40) →
`mdns` (50) → `ssdp` (60). Because `pickBest` re-runs on every record, a late
low-priority source (e.g. SSDP) can never overwrite a better name (e.g. PTR).
Keeping the full map means the report stays auditable: you can always tell why a
device ended up with a given name.

`reverseDns` tries the JVM resolver first (which honours `/etc/hosts` and the
system DNS), then falls back to a direct dnsjava `PTR` lookup — optionally against
an explicit server supplied with `--dns-server`.

## 5. OS fingerprinting

`OsFingerprint` is stateless and unit-testable. `guess(Device)` returns a stable,
lower-case identity or `null`, checking signals in priority order:

1. `fromSysDescr` — textual match on SNMP banners (Cisco IOS, JunOS, Windows,
   ESXi, Darwin/macOS, FreeBSD/pfSense/OPNsense, generic Linux).
2. `fromVendorAndPorts` — port fingerprints (RDP, SMB+RPC, ESXi 902+443,
   SSH-only Unix, printer RAW/IPP) combined with OUI vendor.
3. `fromHostname` — coarse hostname patterns (e.g. `esxi`, `vsphere`).

Because `sysDescr` is the strongest evidence it is consulted first, so a Linux
banner wins over an incidental open RDP port.

## 6. Virtualization

### Fingerprint detection

`VirtualizationDetector` holds an OUI→vendor table and port-based heuristics:

- `guessType` recognizes ESXi, vCenter, Proxmox, KVM, Hyper-V (only when
  `looksLikeWindows` is true), Nutanix and Xen.
- `looksLikeWindows` checks OUI, SNMP `sysDescr`, and Windows-specific port
  combinations, so a workstation with WinRM open is not mistaken for a host.
- `vmVendorByMac` / `isVirtualMachineMac` recognize hypervisor MAC ranges.

### Authenticated discovery

Each hypervisor is discovered through its native API, all of them appending
`VirtualMachine` entries to a shared list:

| Class | API / library |
| --- | --- |
| `EsxiDiscovery`, `VCenterDiscovery` | vijava (VMware SDK) |
| `ProxmoxDiscovery` | Proxmox REST/HTTPS |
| `KvmDiscovery`, `LibvirtDiscovery` | libvirt-java |
| `HyperVDiscovery` | WinRM (winrm4j) |

API results carry `source = "api"`; fingerprint-only hosts carry
`source = "fingerprint"`. `deduplicateVirtualization` collapses duplicates by
IP/ID, preferring API-sourced entries.

### VM ↔ host matching

`VMHostMatcher.match` normalizes MAC addresses, links each `VirtualMachine` to the
host whose `vmMacs` contains it, and fills the VM's `ip` by cross-referencing
discovered devices. This is what turns three separate lists into one coherent
inventory.

## 7. L2 topology

`NeighborSniffer.capture` opens a raw socket on an interface for a bounded time
(`--lldp-duration`) and collects LLDP/CDP frames. `LldpTlvParser` and
`CdpTlvParser` decode them into `NeighborRecord`s. `TopologyBuilder.apply` turns
those records into `TopologyLink` entries (local/remote device, port, VLAN,
management IPs, capabilities).

### 7.1 SNMP bridging tables

LLDP only sees the switch you are plugged into. Router and switch bridging tables
see every access port, so `SnmpScanner` walks them too: `ifName` and `ifAlias`,
`dot1dTpFdbPort` with `dot1dBasePortIfIndex`, the Q-BRIDGE `dot1qTpFdbPort`, and
`dot1qVlanStaticName`.

Each family is indexed differently, so `indexKey` dispatches on the column rather
than assuming one scheme:

| Table | Index | Decoder |
| --- | --- | --- |
| `ipAddr` / `ipRoute` / `ipNetToMedia` | address | `ipFromSuffix` |
| `ifName`, `ifAlias`, `dot1dBasePortIfIndex`, `dot1qVlanStaticName` | one integer | `singleIntKey` |
| `dot1dTpFdbPort`, `dot1dTpFdbAddress` | 6-octet MAC | `macFromSuffix` |
| `dot1qTpFdbPort` | VLAN + MAC | `vlanMacKey` |

Using one decoder everywhere would silently attach every row to the wrong key.

`enrich` consumes this in two ways:

- `describeInterface` labels a subnet from the interface that announced it,
  preferring the operator-set `ifAlias` over `ifName`.
- `applyBridgeTables` records `l2.switch`, `l2.bridgePort`, `l2.portName` and,
  from the Q-BRIDGE table, `vlan.<id>` and `vlan.<id>.name` on each host. Only
  MACs already known from another strategy are matched, so the tables annotate
  hosts rather than inventing them.

`NetworkSegment.vlan` is deliberately left empty: no source states which VLAN an
IP subnet maps to, so any value there would be a guess. VLAN membership is
recorded where it is observed — per host MAC.

## 8. Progress reporting

`Progress` (`discovery/Progress.java`) is an observer the orchestrator calls while it
works: phases, per-segment start/progress/done, and standalone notes. It is not
slf4j, deliberately:

- progress needs in-place redrawing, elapsed time and an on/off switch, none of
  which belong in a logging framework;
- diagnostics and user status must be tunable independently — silencing the pcap4j
  chatter should not also silence the scan's own progress.

Every method has a no-op default and {@link Progress#NONE} is the default wiring, so
`DiscoveryOrchestrator(cfg)` behaves exactly as before and only
`DiscoveryOrchestrator(cfg, progress)` produces output. `ConsoleProgress` implements
it for the CLI, choosing in-place redraw only when `System.console() != null`.

Three details are load-bearing:

- **Throttling lives in the orchestrator**, not the renderer: the callback fires once
  per probe and a /16 is over a million probes.
- **The throttle is a compare-and-set on an `AtomicLong`.** Callbacks arrive from many
  worker threads at once; a plain field let several of them through at the same
  instant, producing interleaved output with timestamps that ran backwards.
- **Counts are incremented inside each probe**, not in the collection loop. Collection
  begins only after every task has been submitted, so a counter there stays at zero
  for the entire sweep and then jumps.

The console anchor is the segment, not a percentage: the number of segments is not
known while a BFS is discovering more of them, so the display shows a lower bound
(`of >=n`) rather than a total that would keep proving wrong.

## 9. Concurrency

Probes run on **virtual threads** via `ProbeExecutor`, a
`newVirtualThreadPerTaskExecutor` with a semaphore cap of `--threads`. The permit is
acquired *before* submission, not inside the task: unbounded submission would create
a virtual thread per (host, port) pair — over a million on a /16 — and the cap is
there to protect the network and the local ephemeral port range, which virtual
threads do not enlarge.

This also fixed a throughput defect. `discoverHosts` used to sweep one host at a time,
waiting for that host's ports before starting the next, and ICMP was a plain
sequential loop. Only about one host's probes were ever outstanding, so `--threads`
had almost no effect and a /22 spent minutes in timeout waits. `tcpSweep` and
`icmpSweep` now submit across all hosts, leaving the cap to decide real concurrency.

`RateLimiter` remains the separate bound on probe *starts* per second (`--pps`).

## 10. Web layer

`JanusApplication` starts a Spring MVC app when `Main` is invoked with `--web`.
`ReportController` exposes read-only endpoints over the latest report:

- `/api/health` — liveness.
- `/api/report` — the `DiscoveryResult` (optionally `?name=`).
- `/api/reports` — available report files.
- `/api/summary` — aggregate counts and duration.

`ReportService` resolves the report path from `janus.report.path`, falling back to
`janus.report.dir`, and deserializes with the shared Jackson configuration.
Static assets (`index.html`, `style.css`, `app.js`) render a d3 force-directed
topology.

## 11. Serialization

Janus runs on **Spring Boot 4 / Jackson 3** (`tools.jackson.*`). `JacksonConfig`
provides:

- A reusable `InetAddress` module (serialize to/from string), since `InetAddress`
  is abstract and not deserializable by default.
- A Spring `JsonMapperBuilderCustomizer` so the web mapper includes the module.
- `cliMapper()` — a pretty-printing mapper used by `Main` for CLI output.

Using one configuration for both CLI and web keeps the JSON contract identical.

## 12. Testing

Unit tests cover the pure logic that is easiest to get wrong and hardest to test
live:

- `DiscoveryConfigTests` — argument parsing and the repeated-`--snmp` fix.
- `VirtualizationDetectorTests` — OUI resolution (including dash/uppercase MACs),
  port fingerprints, VM MAC ranges.
- `OsFingerprintTests` — sysDescr/port/vendor selection and priority ordering.
- `NameResolverTests` — source precedence, aliases accumulation, name
  normalization (trailing dot, IP rejection, whitespace), SSDP header parsing.
- `ReportJsonRoundTripTests` — `InetAddress` ser/deser and failure behavior.
- `JanusApplicationTests` — Spring context loads.

Run everything with `./mvnw test`.
