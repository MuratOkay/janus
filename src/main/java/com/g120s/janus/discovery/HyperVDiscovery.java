package com.g120s.janus.discovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cloudsoft.winrm4j.winrm.WinRmTool;
import io.cloudsoft.winrm4j.winrm.WinRmToolResponse;
import com.g120s.janus.model.VirtualMachine;
import com.g120s.janus.model.VirtualizationHost;

import java.util.*;

public final class HyperVDiscovery {

    private static final ObjectMapper MAP = new ObjectMapper();

    /** Parameters needed to connect to a Hyper-V host. */
    public record Options(String host, int port, boolean useHttps,
                          String domain, String user, String pass) {}

    public static VirtualizationHost discover(Options opt, List<VirtualMachine> sink) throws Exception {
        WinRmTool tool = buildTool(opt);

        // ---- 1) Host basic information + management IPs
        String hostOut = exec(tool, HOST_SCRIPT);
        JsonNode hostJson = MAP.readTree(extractJson(hostOut));
        if (hostJson == null || !hostJson.isObject())
            throw new RuntimeException("Could not read Hyper-V host information (PowerShell output is not JSON)");

        VirtualizationHost host = new VirtualizationHost();
        host.type = "hyperv";
        host.source = "api";
        host.ip = opt.host();
        host.id = "hyperv:" + opt.host();
        host.name = hostJson.path("Hostname").asText(opt.host());
        host.version = hostJson.path("OsVersion").asText(null);

        for (JsonNode ip : hostJson.path("IpAddresses")) {
            String addr = ip.path("IPAddress").asText();
            int len = ip.path("PrefixLength").asInt(24);
            if (!addr.isEmpty()
                    && !addr.startsWith("127.")
                    && !addr.startsWith("169.254.")) {
                host.managementNets.add(addr + "/" + len);
            }
        }

        // ---- 2) VM list + adapter MACs
        String vmOut = exec(tool, VM_SCRIPT);
        JsonNode vms = MAP.readTree(extractJson(vmOut));
        if (vms != null && !vms.isNull()) {
            if (vms.isObject()) vms = MAP.createArrayNode().add(vms);   // single VM → object
            for (JsonNode v : vms) {
                VirtualMachine vm = new VirtualMachine();
                vm.name = v.path("Name").asText("(unnamed)");
                vm.uuid = v.path("Id").asText(null);
                vm.hostId = host.id;
                vm.powerState = v.path("State").asText(null);

                for (JsonNode a : v.path("Adapters")) {
                    String mac = normalizeMac(a.path("MacAddress").asText(""));
                    String sw  = a.path("SwitchName").asText("");
                    if (mac != null) {
                        host.vmMacs.add(mac);
                        if (vm.mac == null) vm.mac = mac;   // treat the first MAC as primary
                    }
                    vm.nics.add((mac == null ? "no-mac" : mac) + "@" + sw);

                    String ipList = a.path("IPAddresses").asText("");
                    if (vm.ip == null && !ipList.isBlank()) {
                        vm.ip = ipList.split(";")[0].trim();   // first IPv4 if integration services are on
                    }
                }
                sink.add(vm);
            }
        }
        return host;
    }

    // ================= PowerShell scripts =================

    /** Host name, OS version and all IPv4 interfaces (including vEthernet). */
    private static final String HOST_SCRIPT = """
        $ErrorActionPreference = 'Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $ips = @()
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and
            $_.IPAddress -notlike '169.254.*' -and
            $_.PrefixOrigin -ne 'WellKnown'
          } |
          ForEach-Object {
            $ips += [PSCustomObject]@{
              IPAddress      = $_.IPAddress
              PrefixLength   = $_.PrefixLength
              InterfaceAlias = $_.InterfaceAlias
            }
          }
        [PSCustomObject]@{
          Hostname    = $env:COMPUTERNAME
          OsVersion   = [System.Environment]::OSVersion.VersionString
          IpAddresses = $ips
        } | ConvertTo-Json -Depth 4 -Compress
        """;

    /** Get-VM + the network adapters of each VM (with the MAC normalized). */
    private static final String VM_SCRIPT = """
        $ErrorActionPreference = 'Stop'
        Import-Module Hyper-V -ErrorAction Stop
        $out = @()
        Get-VM | ForEach-Object {
          $vm = $_
          $ads = @()
          Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object {
            $macRaw = $_.MacAddress
            $mac = ''
            if ($macRaw) {
              $hex = ($macRaw -replace '[^0-9a-fA-F]','').ToLower()
              if ($hex.Length -eq 12) {
                $mac = ($hex -replace '(..)','$1:').TrimEnd(':')
              }
            }
            $ads += [PSCustomObject]@{
              Name        = $_.Name
              MacAddress  = $mac
              SwitchName  = $_.SwitchName
              IPAddresses = if ($_.IPAddresses) { $_.IPAddresses -join ';' } else { '' }
            }
          }
          $out += [PSCustomObject]@{
            Name       = $vm.Name
            Id         = $vm.Id.ToString()
            State      = $vm.State.ToString()
            Generation = $vm.Generation
            Version    = $vm.Version
            Adapters   = $ads
          }
        }
        $out | ConvertTo-Json -Depth 5 -Compress
        """;

    // ================= helpers =================

    private static WinRmTool buildTool(Options opt) {
        String user = (opt.domain() == null || opt.domain().isBlank())
                ? opt.user()
                : opt.domain() + "\\" + opt.user();

        int port = opt.port() == 0 ? (opt.useHttps() ? 5986 : 5985) : opt.port();

        WinRmTool.Builder b = WinRmTool.Builder.builder(opt.host(), user, opt.pass());
        b.authenticationScheme("NTLM");
        b.port(port);
        b.useHttps(opt.useHttps());
        WinRmTool tool = b.build();
        tool.setReceiveTimeout(60_000L);
        tool.setOperationTimeout(120_000L);
        return tool;
    }

    private static String exec(WinRmTool tool, String ps) throws Exception {
        WinRmToolResponse r = tool.executePs(ps);
        if (r.getStatusCode() != 0) {
            throw new RuntimeException(
                "PowerShell exit=" + r.getStatusCode() + " stderr=" + r.getStdErr());
        }
        return r.getStdOut();
    }

    private static String normalizeMac(String raw) {
        if (raw == null) return null;
        String hex = raw.replaceAll("[^0-9a-fA-F]", "").toLowerCase();
        if (hex.length() != 12 || hex.equals("000000000000")) return null;
        return hex.substring(0,2)+":"+hex.substring(2,4)+":"+hex.substring(4,6)+":"+
               hex.substring(6,8)+":"+hex.substring(8,10)+":"+hex.substring(10,12);
    }

    /** WinRM sometimes prepends warnings/logs; this extracts the curly/round bracketed JSON part. */
    private static String extractJson(String s) {
        if (s == null || s.isBlank()) return "null";
        int first = -1, last = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{' || c == '[') { first = i; break; }
        }
        for (int i = s.length() - 1; i >= 0; i--) {
            char c = s.charAt(i);
            if (c == '}' || c == ']') { last = i; break; }
        }
        if (first < 0 || last <= first) return "null";
        return s.substring(first, last + 1);
    }
}