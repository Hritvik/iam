package dev.distracted.iam.dpop;

public record DpopIssuanceState(@com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates nonce,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates replay,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates thumbprint,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates target, String appRegistrationId, String clientId,
        String method, int replayRetentionSeconds, String correlationId) {
    @Override public String toString() { return "DpopIssuanceState[redacted]"; }
}
