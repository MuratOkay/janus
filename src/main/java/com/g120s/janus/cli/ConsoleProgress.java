package com.g120s.janus.cli;

import java.io.PrintStream;
import java.util.List;

import com.g120s.janus.discovery.DiscoveryConfig;
import com.g120s.janus.discovery.Progress;
import com.g120s.janus.discovery.ProgressMode;
import com.g120s.janus.model.NetworkSegment;

/**
 * Prints scan progress to the console.
 *
 * <p>Two rendering modes share one event stream. On a terminal the current-segment
 * line is redrawn in place, which reads as live activity without scrolling the
 * screen away. When output is redirected to a file or a pipe, carriage returns
 * would corrupt the log, so every event becomes a plain line instead. The mode is
 * detected once at construction rather than per event.
 */
public final class ConsoleProgress implements Progress {

    private final PrintStream out;
    private final boolean tty;
    private final long startedAt = System.nanoTime();
    private boolean inPlaceLine;
    
    /** @param tty true when writing to a terminal that supports in-place redraw */
    public ConsoleProgress(PrintStream out, boolean tty) {
        this.out = out;
        this.tty = tty;
    }

    /** Chooses a renderer for the configured mode, or {@link Progress#NONE}. */
    public static Progress forMode(DiscoveryConfig cfg, PrintStream out, boolean tty) {
        ProgressMode mode = cfg.progress == null ? ProgressMode.AUTO : cfg.progress;
        return switch (mode) {
            case NONE -> Progress.NONE;
            case PLAIN -> new ConsoleProgress(out, false);
            case AUTO -> new ConsoleProgress(out, tty);
        };
    }

    @Override
    public synchronized void start(DiscoveryConfig cfg, List<String> seeds) {
        clearInPlace();
        line("Janus network discovery");
        line("  seeds    : " + (seeds.isEmpty() ? "(none)" : String.join(", ", seeds)));
        line("  policy   : " + cfg.sweepPolicy.name().toLowerCase(java.util.Locale.ROOT)
                + " (cap " + cfg.maxHostsPerSubnet + "/segment)"
                + "   threads: " + cfg.threadPool
                + "   pps: " + (cfg.probesPerSecond > 0 ? cfg.probesPerSecond : "unlimited"));
        line("  enabled  : " + enabledStrategies(cfg));
    }

    @Override
    public synchronized void phase(String name) {
        clearInPlace();
        line(elapsed() + " " + name);
    }

    @Override
    public synchronized void segmentStart(NetworkSegment segment, int index, int queued, int targets) {
        clearInPlace();
        // "of >=" because the BFS discovers segments as it goes: a fixed total would
        // be a guess that changes under the user's feet.
        line(elapsed() + " crawling " + segment.cidr + "  (segment " + index
                + " of >=" + (index + queued) + ", queue " + queued + ")  "
                + targets + " target(s)");
    }

    @Override
    public synchronized void segmentProgress(NetworkSegment segment, String stage,
                                             int done, int total, int devices) {
        String text = elapsed() + "   " + segment.cidr + "  " + stage + " " + done + "/" + total
                + "  " + devices + " device(s)";
        if (tty) {
            out.print("\r" + text);
            out.flush();
            inPlaceLine = true;
        } else {
            line(text);
        }
    }

    @Override
    public synchronized void segmentDone(NetworkSegment segment, long millis, int devices) {
        clearInPlace();
        line(elapsed() + " done " + segment.cidr + "  " + devices + " device(s)  ("
                + (millis / 1000.0) + "s)");
    }

    @Override
    public synchronized void note(String message) {
        clearInPlace();
        line(elapsed() + " " + message);
    }

    private void line(String text) {
        out.println(text);
        out.flush();
    }

    /** Erases the in-place line so the next message starts clean. */
    private void clearInPlace() {
        if (!inPlaceLine) return;
        // Carriage return, then overwrite with spaces, then return again: the
        // portable way to blank a line without relying on terminal-specific codes.
        out.print("\r" + " ".repeat(78) + "\r");
        out.flush();
        inPlaceLine = false;
    }

    private String elapsed() {
        long seconds = (System.nanoTime() - startedAt) / 1_000_000_000L;
        return String.format("[%02d:%02d:%02d]", seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    }

    private static String enabledStrategies(DiscoveryConfig cfg) {
        StringBuilder text = new StringBuilder();
        append(text, "tcp", cfg.tcp);
        append(text, "icmp", cfg.icmp);
        append(text, "arp", cfg.arp);
        append(text, "mdns", cfg.mdns);
        append(text, "ssdp", cfg.ssdp);
        append(text, "netbios", cfg.netbios);
        append(text, "snmp", cfg.snmp);
        append(text, "lldp", cfg.lldp);
        append(text, "dns", cfg.dns);
        append(text, "tls", cfg.tlsNames);
        return text.isEmpty() ? "none" : text.toString();
    }

    private static void append(StringBuilder text, String name, boolean enabled) {
        if (!enabled) return;
        if (!text.isEmpty()) text.append(' ');
        text.append(name);
    }
}
