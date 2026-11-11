const hasD3 = typeof d3 !== "undefined";
const svg = hasD3 ? d3.select("#graph") : null;
const errorBox = document.getElementById("error");
const reportSelect = document.getElementById("reports");
let report;
let nodes = [];
let links = [];
let simulation;
let currentLayout = "force";
let currentColor = "type";

const colors = {
    ROUTER: "#ef4444", SWITCH: "#3b82f6", FIREWALL: "#dc2626",
    SERVER: "#22c55e", WORKSTATION: "#9ca3af", PRINTER: "#f97316",
    IOT: "#eab308", MOBILE: "#a855f7", STORAGE: "#14b8a6",
    VIRTUALIZATION_HOST: "#8b5cf6", VIRTUAL_MACHINE: "#c084fc", UNKNOWN: "#6b7280"
};
const edgeColors = { lldp: "#3b82f6", cdp: "#f97316", "vm-host": "#a78bfa" };

async function requestJson(url) {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    return response.json();
}

async function loadReports() {
    const reports = await requestJson("/api/reports");
    const selected = reportSelect.value;
    reportSelect.replaceChildren();
    for (const name of reports) {
        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        reportSelect.append(option);
    }
    if (reports.includes(selected)) reportSelect.value = selected;
}

async function loadReport() {
    errorBox.hidden = true;
    try {
        await loadReports();
        const name = reportSelect.value;
        const query = name ? `?name=${encodeURIComponent(name)}` : "";
        report = await requestJson(`/api/report${query}`);
        buildGraph();
        render();
        updateStats();
        renderSegments();
    } catch (error) {
        errorBox.textContent = `Report failed to load: ${error.message}`;
        errorBox.hidden = false;
        document.getElementById("stats").textContent = "Report failed to load";
    }
}

function buildGraph() {
    const byId = new Map();
    const aliases = new Map();
    const graphLinks = [];
    function add(id, data) {
        if (!id) return;
        const node = { ...byId.get(id), ...data, id };
        byId.set(id, node);
        if (node.ip) aliases.set(`ip:${node.ip}`, id);
        if (node.mac) aliases.set(`mac:${node.mac.toLowerCase()}`, id);
    }
    function resolve(mac, ip) {
        if (mac && aliases.has(`mac:${mac.toLowerCase()}`)) return aliases.get(`mac:${mac.toLowerCase()}`);
        if (ip && aliases.has(`ip:${ip}`)) return aliases.get(`ip:${ip}`);
        return null;
    }

    for (const device of report.devices || []) {
        const id = device.mac ? `mac:${device.mac.toLowerCase()}` : device.ip ? `ip:${device.ip}` : null;
        add(id, {
            label: device.hostname || device.ip || device.mac || id,
            type: device.kind || "UNKNOWN",
            ip: device.ip,
            mac: device.mac,
            hostname: device.hostname,
            discoveredBy: device.discoveredBy || [],
            metadata: device.metadata || {},
            hardware: device.hardware || null,
            ownerHostId: device.ownerHostId || null,
            group: "device"
        });
    }
    for (const host of report.vhosts || []) {
        const id = host.id || `host:${host.ip || host.name}`;
        add(id, {
            label: host.name || host.ip || id,
            type: "VIRTUALIZATION_HOST",
            vhostType: host.type,
            ip: host.ip,
            hostname: host.name,
            version: host.version,
            discoveredBy: [host.source || "api"],
            managementNets: host.managementNets || [],
            metadata: host.metadata || {},
            hardware: host.hardware || null,
            group: "vhost"
        });
    }
    for (const vm of report.vms || []) {
        const knownDevice = vm.mac ? resolve(vm.mac, vm.ip) : resolve(null, vm.ip);
        const id = knownDevice || (vm.uuid ? `vm:${vm.uuid}` : `vm:${vm.hostId}:${vm.name}`);
        add(id, {
            label: vm.name || id,
            type: "VIRTUAL_MACHINE",
            ip: vm.ip,
            mac: vm.mac,
            hostname: vm.name,
            discoveredBy: ["api"],
            metadata: { powerState: vm.powerState, guestOs: vm.guestOs },
            ownerHostId: vm.hostId || null,
            nics: vm.nics || [],
            group: knownDevice ? "device" : "vm"
        });
        if (vm.hostId && byId.has(vm.hostId)) {
            graphLinks.push({ source: id, target: vm.hostId, type: "vm-host" });
        }
    }
    for (const device of byId.values()) {
        if (device.ownerHostId && byId.has(device.ownerHostId)) {
            graphLinks.push({ source: device.id, target: device.ownerHostId, type: "vm-host" });
        }
    }
    for (const link of report.links || []) {
        const source = resolve(link.localMac, link.localDevice);
        const target = resolve(link.remoteChassisId, link.remoteDevice)
            || [...byId.values()].find(node => link.remoteSystemName
                && node.hostname?.toLowerCase() === link.remoteSystemName.toLowerCase())?.id;
        if (!source || !target || source === target) continue;
        const type = (link.protocol || "").toLowerCase();
        if (!graphLinks.some(edge => edge.type === type
                && ((edge.source === source && edge.target === target)
                    || (edge.source === target && edge.target === source)))) {
            graphLinks.push({
                source, target, type,
                localPort: link.localIface,
                remotePort: link.remotePort,
                vlan: link.localVlan
            });
        }
    }
    nodes = [...byId.values()];
    links = graphLinks;
}

function render() {
    if (simulation) simulation.stop();
    svg.selectAll("*").remove();
    const width = svg.node().clientWidth;
    const height = svg.node().clientHeight;
    const visibleNodes = currentLayout === "virt"
        ? nodes.filter(node => node.group === "vhost" || node.group === "vm"
            || node.type === "VIRTUAL_MACHINE" || node.type === "VIRTUALIZATION_HOST")
        : nodes.slice();
    const visibleIds = new Set(visibleNodes.map(node => node.id));
    const visibleLinks = links.filter(link => visibleIds.has(endpointId(link.source))
        && visibleIds.has(endpointId(link.target)));
    const root = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.1, 4]).on("zoom", event => {
        root.attr("transform", event.transform);
    }));
    simulation = d3.forceSimulation(visibleNodes)
        .force("link", d3.forceLink(visibleLinks).id(node => node.id)
            .distance(link => link.type === "vm-host" ? 65 : 130))
        .force("charge", d3.forceManyBody().strength(-400))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collide", d3.forceCollide(node => node.type === "VIRTUALIZATION_HOST" ? 20 : 13));
    if (currentLayout === "vlan") {
        simulation.force("x", d3.forceX(node => vlanX(node, width)).strength(0.25));
        simulation.force("y", d3.forceY(height / 2).strength(0.05));
    }
    const edge = root.append("g").selectAll("line").data(visibleLinks).join("line")
        .attr("stroke", link => edgeColors[link.type] || "#6b7280")
        .attr("stroke-width", link => link.type === "vm-host" ? 1 : 2)
        .attr("stroke-dasharray", link => link.type === "vm-host" ? "4,4" : null);
    const circle = root.append("g").selectAll("circle").data(visibleNodes).join("circle")
        .attr("r", node => node.type === "VIRTUALIZATION_HOST" ? 14 : node.type === "VIRTUAL_MACHINE" ? 8 : 10)
        .attr("fill", color)
        .attr("stroke", node => node.group === "vhost" ? "#facc15" : "#111827")
        .attr("stroke-width", node => node.group === "vhost" ? 3 : 1)
        .call(d3.drag()
            .on("start", (event, node) => {
                if (!event.active) simulation.alphaTarget(0.25).restart();
                node.fx = node.x; node.fy = node.y;
            })
            .on("drag", (event, node) => { node.fx = event.x; node.fy = event.y; })
            .on("end", (event, node) => {
                if (!event.active) simulation.alphaTarget(0);
                node.fx = null; node.fy = null;
            }))
        .on("click", (_event, node) => showDetails(node));
    const label = root.append("g").selectAll("text").data(visibleNodes).join("text")
        .attr("class", "node-label")
        .attr("text-anchor", "middle")
        .text(node => shorten(node.label, 24));
    simulation.on("tick", () => {
        edge.attr("x1", link => link.source.x).attr("y1", link => link.source.y)
            .attr("x2", link => link.target.x).attr("y2", link => link.target.y);
        circle.attr("cx", node => node.x).attr("cy", node => node.y);
        label.attr("x", node => node.x).attr("y", node => node.y - 14);
    });
    document.getElementById("search").oninput = event => {
        const query = event.target.value.trim().toLowerCase();
        circle.attr("opacity", node => matches(node, query) ? 1 : 0.12);
        label.attr("opacity", node => matches(node, query) ? 1 : 0.08);
        edge.attr("opacity", query ? 0.08 : 1);
    };
    updateLegend();
}

function color(node) {
    if (currentColor === "source") {
        const sources = node.discoveredBy || [];
        if (sources.includes("snmp")) return "#3b82f6";
        if (sources.includes("lldp") || sources.includes("cdp")) return "#ef4444";
        if (sources.includes("arp")) return "#22c55e";
        if (sources.includes("tcp") || sources.includes("icmp")) return "#eab308";
        if (sources.includes("mdns") || sources.includes("ssdp")) return "#a855f7";
    } else if (currentColor === "vlan") {
        const vlan = getVlan(node);
        return vlan == null ? "#6b7280" : d3.interpolateRainbow((vlan % 20) / 20);
    }
    return colors[node.type] || colors.UNKNOWN;
}

function getVlan(node) {
    if (node.metadata?.nativeVlan) return Number(node.metadata.nativeVlan);
    const key = Object.keys(node.metadata || {}).find(name => name.startsWith("vlan."));
    return key ? Number(key.slice(5)) : null;
}

function vlanX(node, width) {
    const vlan = getVlan(node);
    return vlan == null ? width / 2 : 40 + (vlan % 20) * (width - 80) / 20;
}

function endpointId(endpoint) { return typeof endpoint === "object" ? endpoint.id : endpoint; }
function shorten(value, limit) { return value?.length > limit ? `${value.slice(0, limit - 1)}…` : value || ""; }
/**
 * Switch port label, combining the bridge port number with the interface name the
 * switch reports for it (e.g. "12 (Gi1/0/12)") when both are known.
 */
function switchPort(node) {
    const port = node.metadata?.["l2.bridgePort"];
    const name = node.metadata?.["l2.portName"];
    if (port && name) return `${port} (${name})`;
    return port || name || null;
}

/** "8 x Intel(R) Core..." — the core count is omitted when the model alone is known. */
function hardwareCpu(node) {
    const hw = node.hardware;
    if (!hw) return null;
    const parts = [];
    if (hw.cpuCores) parts.push(`${hw.cpuCores} core${hw.cpuCores === 1 ? "" : "s"}`);
    if (hw.cpuType) parts.push(hw.cpuType);
    return parts.length ? parts.join(" \u00d7 ") : null;
}

/** Binary units, because RAM is always sold and reported in GiB-style powers of two. */
function formatBytes(bytes) {
    if (typeof bytes !== "number" || bytes <= 0) return null;
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit++;
    }
    return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function hardwareMemory(node) {
    return formatBytes(node.hardware?.memTotalBytes);
}

/** One line per filesystem: "mount  total (free free)". */
function hardwareDisks(node) {
    const disks = node.hardware?.disks;
    if (!disks?.length) return null;
    return disks.map(disk => {
        const total = formatBytes(disk.totalBytes);
        const free = formatBytes(disk.freeBytes);
        return free ? `${disk.mount}  ${total} (${free} free)` : `${disk.mount}  ${total}`;
    }).join("\n");
}

function matches(node, query) {
    return !query || [node.ip, node.mac, node.hostname, node.label, node.type]
        .filter(Boolean).join(" ").toLowerCase().includes(query);
}

function showDetails(node) {
    document.getElementById("details").hidden = false;
    document.getElementById("title").textContent = node.label || node.id;
    const rows = [
        ["Type", node.type], ["IP", node.ip], ["MAC", node.mac],
        ["Hostname", node.hostname], ["Hypervisor", node.vhostType],
        ["Version", node.version], ["Owner", node.ownerHostId],
        ["Source", node.discoveredBy?.join(", ")],
        ["Management networks", node.managementNets?.join(", ")],
        ["NICs", node.nics?.join(", ")],
        ["Switch", node.metadata?.["l2.switch"]],
        ["Switch port", switchPort(node)],
        ["CPU", hardwareCpu(node)],
        ["Memory", hardwareMemory(node)],
        ["Disks", hardwareDisks(node)],
        ["Hardware source", node.hardware?.source]
    ];
    for (const [key, value] of Object.entries(node.metadata || {})) rows.push([key, value]);
    const table = document.createElement("table");
    for (const [key, value] of rows) {
        if (value == null || value === "") continue;
        const row = table.insertRow();
        row.insertCell().textContent = key;
        row.insertCell().textContent = String(value);
    }
    const content = document.getElementById("content");
    content.replaceChildren(table);
}

function updateLegend() {
    const legend = document.getElementById("legend");
    legend.replaceChildren();
    const categories = currentColor === "type"
        ? [...new Set(nodes.map(node => node.type))].sort()
        : currentColor === "source"
            ? ["SNMP", "LLDP/CDP", "ARP", "TCP/ICMP", "mDNS/SSDP", "Other"]
            : [...new Set(nodes.map(getVlan).filter(value => value != null))].sort((a, b) => a - b).map(vlan => `VLAN ${vlan}`);
    for (const category of categories) {
        const item = document.createElement("div");
        item.className = "legend-item";
        const swatch = document.createElement("span");
        swatch.className = "swatch";
        const sample = currentColor === "type" ? { type: category }
            : currentColor === "source" ? { discoveredBy: sourceNames(category) }
            : { metadata: { nativeVlan: category.replace("VLAN ", "") } };
        swatch.style.background = color(sample);
        item.append(swatch, document.createTextNode(category));
        legend.append(item);
    }
}

function sourceNames(category) {
    return ({
        SNMP: ["snmp"], "LLDP/CDP": ["lldp"], ARP: ["arp"],
        "TCP/ICMP": ["tcp"], "mDNS/SSDP": ["mdns"]
    })[category] || [];
}

function cidrRange(cidr) {
    const [address, prefixText] = String(cidr || "").split("/");
    const prefix = Number(prefixText);
    const octets = String(address || "").split(".").map(Number);
    if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)
            || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
    const value = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    return { from: (value & mask) >>> 0, to: ((value & mask) >>> 0) + (2 ** (32 - prefix)) - 1, prefix };
}

function devicesIn(segment) {
    const range = cidrRange(segment.cidr);
    if (!range) return 0;
    return (report.devices || []).filter(device => {
        const host = cidrRange(`${device.ip}/32`);
        return host && host.from >= range.from && host.from <= range.to;
    }).length;
}

// Segments arrive flat. Rebuild the parent/child shape the crawl produced so the
// inventory reads as a network hierarchy instead of an unsorted list.
function segmentTree() {
    const segments = report.segments || [];
    const byCidr = new Map(segments.map(segment => [segment.cidr, segment]));
    const children = new Map();
    const roots = [];
    for (const segment of segments) {
        const parent = segment.parentCidr && byCidr.has(segment.parentCidr)
            ? segment.parentCidr : null;
        if (parent) {
            if (!children.has(parent)) children.set(parent, []);
            children.get(parent).push(segment);
        } else {
            roots.push(segment);
        }
    }
    const ordered = list => list.slice().sort((a, b) => a.cidr.localeCompare(b.cidr));
    return { roots: ordered(roots), children };
}

function renderSegments() {
    const tree = document.getElementById("segmentTree");
    const count = document.getElementById("subnetCount");
    tree.replaceChildren();
    if (!report || !report.segments?.length) {
        if (count) count.textContent = "";
        const item = document.createElement("li");
        item.className = "empty";
        item.textContent = "No subnets reported.";
        tree.append(item);
        return;
    }
    if (count) count.textContent = `(${report.segments.length})`;

    const { roots, children } = segmentTree();
    const addRow = (segment, level) => {
        const item = document.createElement("li");
        item.style.paddingLeft = `${level * 12}px`;
        const cidr = document.createElement("span");
        cidr.className = "cidr";
        cidr.textContent = segment.cidr;
        item.append(cidr);

        // Coverage: a range that was only partly probed must not look empty.
        const probed = Number(segment.hostsProbed || 0);
        const total = Number(segment.hostsTotal || 0);
        const parts = [];
        if (total) parts.push(`${probed}/${total} probed`);
        if (segment.sweepPolicy) parts.push(segment.sweepPolicy);
        const devices = devicesIn(segment);
        parts.push(`${devices} device${devices === 1 ? "" : "s"}`);
        if (segment.description) parts.push(segment.description);

        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = parts.join(" · ");
        item.append(meta);

        if (segment.coveredBy) {
            const flag = document.createElement("span");
            flag.className = "flag";
            flag.textContent = `covered by ${segment.coveredBy}`;
            item.append(flag);
        }
        if (segment.discoveredBy?.length) {
            const source = document.createElement("div");
            source.className = "meta";
            source.textContent = segment.discoveredBy.join(", ");
            item.append(source);
        }
        tree.append(item);
        for (const child of children.get(segment.cidr) || []) addRow(child, level + 1);
    };
    for (const root of roots) addRow(root, 0);
}

function updateStats() {
    const seconds = Math.max(0, report.finishedAt - report.startedAt) / 1000;
    document.getElementById("stats").textContent =
        `${report.devices?.length || 0} devices · ${report.vhosts?.length || 0} hosts · `
        + `${report.vms?.length || 0} VMs · ${report.segments?.length || 0} subnets · `
        + `${report.links?.length || 0} L2 links · ${seconds.toFixed(1)} s`;
}

document.getElementById("refresh").onclick = loadReport;
reportSelect.onchange = loadReport;
document.getElementById("layout").onchange = event => { currentLayout = event.target.value; render(); };
document.getElementById("color").onchange = event => { currentColor = event.target.value; render(); };
document.getElementById("close").onclick = () => { document.getElementById("details").hidden = true; };
svg.on("click", () => { document.getElementById("details").hidden = true; });
window.addEventListener("resize", () => simulation?.alpha(0.2).restart());

if (!hasD3) {
    errorBox.textContent = "Failed to load D3; check the network connection.";
    errorBox.hidden = false;
} else {
    loadReport();
}
