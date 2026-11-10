package com.g120s.janus.discovery;

import java.util.Locale;

/** How progress is rendered on the console. */
public enum ProgressMode {

    /** Redraw in place when attached to a terminal, plain lines when redirected. */
    AUTO,

    /** One line per event, never overwrite. Safe for logs and CI. */
    PLAIN,

    /** No progress output at all. */
    NONE;

    public static ProgressMode parse(String value, String option) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(option + " must not be blank");
        }
        try {
            return valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(option
                    + " must be one of auto, plain, none (got: " + value + ")", e);
        }
    }
}
