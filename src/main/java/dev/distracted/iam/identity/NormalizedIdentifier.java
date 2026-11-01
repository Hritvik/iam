package dev.distracted.iam.identity;

import java.util.Objects;

public record NormalizedIdentifier(IdentifierType type, short normalizationVersion, String canonical, String display) {
    public NormalizedIdentifier {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(canonical, "canonical");
        Objects.requireNonNull(display, "display");
        if (normalizationVersion != 1) throw new IllegalArgumentException("normalization_version_invalid");
    }

    @Override public String toString() { return "NormalizedIdentifier[protected]"; }
}
