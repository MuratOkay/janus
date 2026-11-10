package com.g120s.janus.cli;

import com.g120s.janus.discovery.DiscoveryConfig;
import com.g120s.janus.discovery.Progress;
import com.g120s.janus.discovery.ProgressMode;
import com.g120s.janus.model.NetworkSegment;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * When output is redirected, a carriage return corrupts the log: the line gets
 * overwritten in the file instead of on a terminal. Plain mode must therefore never
 * emit one, while terminal mode must use it to redraw in place.
 */
class ConsoleProgressTests {

    @Test
    void plainModeNeverEmitsCarriageReturns() {
        String text = render(false, out -> {
            out.segmentStart(segment(), 1, 0, 10);
            out.segmentProgress(segment(), "tcp", 5, 10, 1);
            out.segmentDone(segment(), 120, 1);
        });

        assertFalse(text.contains("\r"), "a redirected log must stay line-oriented");
        assertTrue(text.contains("10.0.0.0/24"));
        assertTrue(text.contains("5/10"));
    }

    @Test
    void terminalModeRedrawsInPlace() {
        String text = render(true, out -> out.segmentProgress(segment(), "tcp", 5, 10, 1));

        assertTrue(text.contains("\r"), "a terminal should reuse one line");
        assertTrue(text.contains("5/10"));
    }

    @Test
    void inPlaceLineIsClearedBeforeDurableOutput() {
        String text = render(true, out -> {
            out.segmentProgress(segment(), "tcp", 5, 10, 1);
            out.note("something durable");
        });

        int redrawn = text.indexOf("5/10");
        int padding = text.lastIndexOf(" ".repeat(78), text.indexOf("something durable"));
        assertTrue(padding > redrawn,
                "the in-place line must be blanked after the redraw");
        assertTrue(text.indexOf("something durable") > padding,
                "and before the durable message");
    }

    @Test
    void startLineSummarisesTheConfiguration() {
        DiscoveryConfig cfg = new DiscoveryConfig();
        cfg.tcp = true;
        cfg.icmp = false;
        cfg.sweepPolicy = com.g120s.janus.discovery.SweepPolicy.SAMPLE;
        cfg.probesPerSecond = 250;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream stream = new PrintStream(buffer, true, StandardCharsets.UTF_8);

        new ConsoleProgress(stream, false).start(cfg, List.of("10.0.0.0/24"));
        String text = buffer.toString(StandardCharsets.UTF_8);

        assertTrue(text.contains("10.0.0.0/24"), text);
        assertTrue(text.contains("sample"), "the sweep policy is shown");
        assertTrue(text.contains("250"), "the rate limit is shown");
        assertTrue(text.contains("tcp"));
        assertFalse(text.contains("icmp"), "disabled strategies are not listed");
    }

    @Test
    void noneModeProducesNoRendererAtAll() {
        DiscoveryConfig cfg = new DiscoveryConfig();
        cfg.progress = ProgressMode.NONE;

        assertSame(Progress.NONE,
                ConsoleProgress.forMode(cfg, new PrintStream(new ByteArrayOutputStream(), true), true));
    }

    @Test
    void autoModeFollowsTheDetectedTerminal() {
        DiscoveryConfig cfg = new DiscoveryConfig();
        cfg.progress = ProgressMode.AUTO;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new ConsoleProgress(buffer2(buffer), true).segmentProgress(segment(), "tcp", 1, 2, 0);
        assertTrue(buffer.toString(StandardCharsets.UTF_8).contains("\r"),
                "auto on a terminal redraws in place");

        ByteArrayOutputStream piped = new ByteArrayOutputStream();
        new ConsoleProgress(buffer2(piped), false).segmentProgress(segment(), "tcp", 1, 2, 0);
        assertFalse(piped.toString(StandardCharsets.UTF_8).contains("\r"));
    }

    private static NetworkSegment segment() {
        NetworkSegment segment = new NetworkSegment("10.0.0.0/24");
        segment.hostsTotal = 254;
        segment.hostsProbed = 254;
        return segment;
    }

    private static PrintStream buffer2(ByteArrayOutputStream buffer) {
        return new PrintStream(buffer, true, StandardCharsets.UTF_8);
    }

    private interface Script {
        void run(ConsoleProgress progress);
    }

    private static String render(boolean tty, Script script) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        script.run(new ConsoleProgress(buffer2(buffer), tty));
        return buffer.toString(StandardCharsets.UTF_8);
    }
}
