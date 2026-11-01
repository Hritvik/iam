package dev.distracted.iam.messaging;

import java.util.regex.Pattern;

public record CorrelationId(String value) {
    private static final Pattern FORMAT = Pattern.compile("^cor_[A-Za-z0-9_-]{16,128}$");

    public CorrelationId {
        if (value == null || !FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("correlation ID is invalid");
        }
    }
}
