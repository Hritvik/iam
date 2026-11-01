package dev.distracted.iam.platform.crypto;

import java.util.Objects;
import java.util.regex.Pattern;

public record CapabilityMetadata(
        CapabilityPurpose purpose,
        String provider,
        String keyReference,
        String algorithm) {
    private static final Pattern PROVIDER = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{1,31}");
    private static final Pattern KEY_REFERENCE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9:/.@_-]{2,127}");
    private static final Pattern ALGORITHM = Pattern.compile("[A-Z0-9][A-Z0-9-]{1,31}");

    public CapabilityMetadata {
        Objects.requireNonNull(purpose, "purpose");
        requireMatch(provider, PROVIDER, "provider");
        requireMatch(keyReference, KEY_REFERENCE, "keyReference");
        requireMatch(algorithm, ALGORITHM, "algorithm");
    }

    private static void requireMatch(String value, Pattern pattern, String field) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " is missing or outside its bounded format");
        }
    }
}

