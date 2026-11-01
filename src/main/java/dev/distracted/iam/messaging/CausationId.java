package dev.distracted.iam.messaging;

import java.util.regex.Pattern;

public record CausationId(String value) {
    private static final Pattern FORMAT = Pattern.compile("^cau_[A-Za-z0-9_-]{16,128}$");

    public CausationId {
        if (value == null || !FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("causation ID is invalid");
        }
    }
}
