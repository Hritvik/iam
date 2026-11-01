package dev.distracted.iam.token;

import java.util.regex.Pattern;

public record DpopKeyThumbprint(@com.fasterxml.jackson.annotation.JsonIgnore String value) {
    private static final Pattern FORMAT = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    public DpopKeyThumbprint {
        if (value == null || !FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("DPoP key thumbprint is invalid");
        }
        try {
            var decoded = java.util.Base64.getUrlDecoder().decode(value + "=");
            var canonical = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
            if (decoded.length != 32 || !value.equals(canonical)) {
                throw new IllegalArgumentException("DPoP key thumbprint is invalid");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("DPoP key thumbprint is invalid");
        }
    }

    @Override public String toString() { return "DpopKeyThumbprint[redacted]"; }
}
