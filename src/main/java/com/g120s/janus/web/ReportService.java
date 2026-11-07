package com.g120s.janus.web;

import tools.jackson.databind.ObjectMapper;
import com.g120s.janus.model.DiscoveryResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

@Service
public class ReportService {
    private final ObjectMapper mapper;
    private final Path reportPath;
    private final Path reportDirectory;

    public ReportService(ObjectMapper mapper,
                         @Value("${janus.report.path:discovery-report.json}") String reportPath,
                         @Value("${janus.report.dir:reports}") String reportDirectory) {
        this.mapper = mapper;
        this.reportPath = Paths.get(reportPath);
        this.reportDirectory = Paths.get(reportDirectory);
    }

    public DiscoveryResult loadLatest(String name) {
        Path selected = resolveReport(name);
        if (!Files.isRegularFile(selected)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Report not found: " + selected.toAbsolutePath());
        }
        try {
            return mapper.readValue(selected.toFile(), DiscoveryResult.class);
        } catch (tools.jackson.core.JacksonException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Report could not be read: " + selected.toAbsolutePath(), e);
        }
    }

    private Path resolveReport(String name) {
        if (name == null || name.isBlank()) {
            if (Files.isRegularFile(reportPath)) return reportPath;
            if (!reportPath.isAbsolute()) return reportDirectory.resolve(reportPath);
            return reportPath;
        }
        Path requested = Paths.get(name);
        if (requested.isAbsolute() || requested.getNameCount() != 1
                || !requested.getFileName().toString().endsWith(".json")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid report name");
        }
        for (Path directory : List.of(reportDirectory, Paths.get("."))) {
            Path candidate = directory.resolve(requested).normalize();
            if (Files.isRegularFile(candidate)) return candidate;
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Report not found: " + name);
    }

    public List<String> listReports() {
        Set<String> names = new TreeSet<>();
        collectReports(reportDirectory, names);
        collectReports(Paths.get("."), names);
        return List.copyOf(names);
    }

    private static void collectReports(Path directory, Set<String> names) {
        if (!Files.isDirectory(directory)) return;
        try (Stream<Path> paths = Files.list(directory)) {
            paths.filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.endsWith(".json"))
                    .forEach(names::add);
        } catch (IOException e) {
            throw new UncheckedIOException("Report directory could not be read: " + directory.toAbsolutePath(), e);
        }
    }
}
