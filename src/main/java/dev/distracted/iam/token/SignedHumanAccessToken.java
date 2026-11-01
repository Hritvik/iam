package dev.distracted.iam.token;

import java.util.Objects;

public final class SignedHumanAccessToken {
    private final String compactValue;

    public SignedHumanAccessToken(String compactValue) {
        this.compactValue = Objects.requireNonNull(compactValue, "compact token is required");
        if (compactValue.length() > 8192 || compactValue.split("\\.", -1).length != 3) {
            throw new IllegalArgumentException("compact token is invalid");
        }
    }

    public String compactValue() { return compactValue; }

    @Override public String toString() { return "SignedHumanAccessToken[redacted]"; }
}
