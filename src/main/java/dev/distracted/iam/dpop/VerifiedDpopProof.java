package dev.distracted.iam.dpop;

import java.time.Instant;

public record VerifiedDpopProof(String method, String target, Instant issuedAt,
                                @com.fasterxml.jackson.annotation.JsonIgnore String jti,
                                @com.fasterxml.jackson.annotation.JsonIgnore String nonce,
                                @com.fasterxml.jackson.annotation.JsonIgnore String keyThumbprint) {
    @Override public String toString() { return "VerifiedDpopProof[redacted]"; }
}
