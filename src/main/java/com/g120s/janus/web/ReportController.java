package com.g120s.janus.web;

import com.g120s.janus.model.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ReportController {
    private final ReportService service;

    public ReportController(ReportService service) {
        this.service = service;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "up", "time", Instant.now().toString());
    }

    @GetMapping("/report")
    public DiscoveryResult report(@RequestParam(required = false) String name) {
        return service.loadLatest(name);
    }

    @GetMapping("/reports")
    public List<String> reports() {
        return service.listReports();
    }

    @GetMapping("/summary")
    public Map<String, Object> summary(@RequestParam(required = false) String name) {
        DiscoveryResult result = service.loadLatest(name);
        Map<String, Integer> byType = new TreeMap<>();
        for (Device device : result.devices) {
            if (device.kind != null) byType.merge(device.kind.name(), 1, Integer::sum);
        }
        Map<String, Integer> byProtocol = new TreeMap<>();
        for (TopologyLink link : result.links) {
            if (link.protocol != null) byProtocol.merge(link.protocol, 1, Integer::sum);
        }
        return Map.of(
                "devices", result.devices.size(),
                "vhosts", result.vhosts.size(),
                "vms", result.vms.size(),
                "segments", result.segments.size(),
                "links", result.links.size(),
                "byType", byType,
                "byProtocol", byProtocol,
                "startedAt", result.startedAt,
                "finishedAt", result.finishedAt,
                "durationMs", result.finishedAt - result.startedAt);
    }
}
