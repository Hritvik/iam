package dev.distracted.iam.dpop;

public record DpopChallengeState(@com.fasterxml.jackson.annotation.JsonIgnore String nonceId,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopState nonce,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates replay,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates thumbprint,
        @com.fasterxml.jackson.annotation.JsonIgnore ProtectedDpopCandidates target,
        String appRegistrationId, String clientId, String method, int nonceLifetimeSeconds,
        int replayRetentionSeconds, String correlationId) {
    @Override public String toString() { return "DpopChallengeState[redacted]"; }
}
