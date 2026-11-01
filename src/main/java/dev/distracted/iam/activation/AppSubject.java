package dev.distracted.iam.activation;

import java.util.regex.Pattern;

public record AppSubject(String value) {
    private static final Pattern FORMAT = Pattern.compile("^aps_[A-Za-z0-9_-]{24}$");

    public AppSubject {
        if (value == null || !FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("app subject is invalid");
        }
    }

    @Override public String toString() { return "AppSubject[redacted]"; }
}
