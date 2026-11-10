package com.g120s.janus.discovery;

import com.g120s.janus.model.NetworkSegment;

import java.util.List;

/**
 * Receives user-facing progress while a scan runs.
 *
 * <p>This is an observer rather than logging: progress needs in-place redrawing,
 * a notion of elapsed time, and the ability to be switched off entirely for
 * scripted use, none of which belong in a logging framework. Diagnostics still go
 * through slf4j, so the two can be tuned independently.
 *
 * <p>Every method has a no-op default so new events can be added without breaking
 * existing implementations, and {@link #NONE} is the default wiring — a caller that
 * does not ask for progress pays nothing.
 */
public interface Progress {

    /** Suppresses all output; the default for library use and for tests. */
    Progress NONE = new Progress() { };

    /** The scan is starting. {@code seeds} is informational only. */
    default void start(DiscoveryConfig cfg, List<String> seeds) { }

    /** A named phase began, such as an LLDP capture or the virtualization pass. */
    default void phase(String name) { }

    /** A segment is about to be probed. {@code targets} may be 0 under KNOWN policy. */
    default void segmentStart(NetworkSegment segment, int index, int queued, int targets) { }

    /**
     * Periodic update while a segment is being probed. {@code stage} names the
     * strategy producing the count (tcp, icmp), so two sweeps over the same range
     * cannot look like one counter that restarted.
     */
    default void segmentProgress(NetworkSegment segment, String stage, int done, int total, int devices) { }

    /** A segment finished; {@code millis} is how long it took. */
    default void segmentDone(NetworkSegment segment, long millis, int devices) { }

    /** A standalone message: a skip, a warning, or the final summary. */
    default void note(String message) { }
}
