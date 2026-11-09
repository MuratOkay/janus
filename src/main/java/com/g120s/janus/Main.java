package com.g120s.janus;

import com.g120s.janus.configuration.JacksonConfig;
import com.g120s.janus.discovery.DiscoveryConfig;
import com.g120s.janus.discovery.DiscoveryOrchestrator;
import com.g120s.janus.model.DiscoveryResult;
import org.springframework.boot.SpringApplication;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--web".equals(args[0])) {
            SpringApplication.run(JanusApplication.class, Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        if (args.length == 0) {
            printUsage();
            return;
        }
        DiscoveryConfig cfg = DiscoveryConfig.fromArgs(args);
        DiscoveryResult r = new DiscoveryOrchestrator(cfg).run();

        JacksonConfig.cliMapper().writeValue(new java.io.File(cfg.outputPath), r);

        System.out.printf("Done. %d devices, %d virtual machines, %d hosts, %d network segments, %d L2 links.%n",
                r.devices.size(), r.vms.size(), r.vhosts.size(), r.segments.size(), r.links.size());
        if (!r.warnings.isEmpty()) {
            System.out.println("Warnings:");
            r.warnings.forEach(w -> System.out.println("  - " + w));
        }
        System.out.println("For the web interface: java -jar janus.jar --web");
    }

    private static void printUsage() {
        System.out.println("""
                Usage:
                  java -jar janus.jar [options]
                Example:
                  --cidr 192.168.1.0/24 --cidr 10.0.0.0/24 --snmp public --out report.json
                Options:
                  --cidr CIDR          Seed network (repeatable; defaults to local networks)
                  --snmp COMMUNITY    SNMP v2c community (repeatable)
                  --no-tcp --no-icmp --no-arp --no-mdns --no-ssdp --no-netbios --no-snmp
                  --no-lldp --lldp-duration MS
                  --no-dns --no-tls-names --dns-server IP --dns-timeout MS
                  --threads N --tcp-timeout MS --snmp-timeout MS
                  --max-subnets N --max-depth N --max-hosts-per-subnet N --out FILE
                  --esxi HOST,USER,PASSWORD
                  --proxmox HOST,PORT,USER,PASSWORD
                  --kvm HOST,USER,PASSWORD
                  --hyperv HOST --hyperv-user USER --hyperv-pass PASS [--hyperv-domain DOMAIN]
                  --vcenter URL --vcenter-user USER --vcenter-pass PASS [--vcenter-insecure]
                  --libvirt URI
                  --web [--server.port=8080] [--janus.report.path=discovery-report.json]
                Use only on networks you are authorized to assess.
                """);
    }
}
