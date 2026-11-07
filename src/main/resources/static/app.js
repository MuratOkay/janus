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
    } catch (error) {
        errorBox.textContent = `Rapor yüklenemedi: ${error.message}`;
        errorBox.hidden = false;
        document.getElementById("stats").textContent = "Rapor yüklenemedi";
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
function matches(node, query) {
    return !query || [node.ip, node.mac, node.hostname, node.label, node.type]
        .filter(Boolean).join(" ").toLowerCase().includes(query);
}

function showDetails(node) {
    document.getElementById("details").hidden = false;
    document.getElementById("title").textContent = node.label || node.id;
    const rows = [
        ["Tip", node.type], ["IP", node.ip], ["MAC", node.mac],
        ["Hostname", node.hostname], ["Hipervizör", node.vhostType],
        ["Sürüm", node.version], ["Sahip", node.ownerHostId],
        ["Kaynak", node.discoveredBy?.join(", ")],
        ["Yönetim ağları", node.managementNets?.join(", ")],
        ["NIC'ler", node.nics?.join(", ")]
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
            ? ["SNMP", "LLDP/CDP", "ARP", "TCP/ICMP", "mDNS/SSDP", "Diğer"]
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

function updateStats() {
    const seconds = Math.max(0, report.finishedAt - report.startedAt) / 1000;
    document.getElementById("stats").textContent =
        `${report.devices?.length || 0} cihaz · ${report.vhosts?.length || 0} host · `
        + `${report.vms?.length || 0} VM · ${report.links?.length || 0} L2 bağlantısı · ${seconds.toFixed(1)} sn`;
}

document.getElementById("refresh").onclick = loadReport;
reportSelect.onchange = loadReport;
document.getElementById("layout").onchange = event => { currentLayout = event.target.value; render(); };
document.getElementById("color").onchange = event => { currentColor = event.target.value; render(); };
document.getElementById("close").onclick = () => { document.getElementById("details").hidden = true; };
svg.on("click", () => { document.getElementById("details").hidden = true; });
window.addEventListener("resize", () => simulation?.alpha(0.2).restart());

if (!hasD3) {
    errorBox.textContent = "D3 yüklenemedi; ağ bağlantısını kontrol edin.";
    errorBox.hidden = false;
} else {
    loadReport();
}
