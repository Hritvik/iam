package dev.distracted.iam.dpop;

import java.util.regex.Pattern;

public record DpopNonceMaterial(@com.fasterxml.jackson.annotation.JsonIgnore String nonceId,
                                @com.fasterxml.jackson.annotation.JsonIgnore String rawNonce) {
    private static final Pattern ID = Pattern.compile("^dpn_[A-Za-z0-9_-]{22}$");
    private static final Pattern NONCE = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    public DpopNonceMaterial {
        if (nonceId == null || rawNonce == null || !ID.matcher(nonceId).matches()
                || !NONCE.matcher(rawNonce).matches()) throw new IllegalArgumentException("dpop_nonce_material_invalid");
    }
    @Override public String toString() { return "DpopNonceMaterial[redacted]"; }
}
