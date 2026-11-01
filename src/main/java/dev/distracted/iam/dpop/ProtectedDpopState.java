package dev.distracted.iam.dpop;

public record ProtectedDpopState(short keyVersion, @com.fasterxml.jackson.annotation.JsonIgnore byte[] digest) {
    public ProtectedDpopState {
        if (keyVersion < 1 || digest == null || digest.length != 32) {
            throw new IllegalArgumentException("dpop_state_digest_invalid");
        }
        digest = digest.clone();
    }

    @Override public byte[] digest() { return digest.clone(); }
    @Override public String toString() { return "ProtectedDpopState[redacted]"; }
}
