package dev.distracted.iam.messaging;

public record OnboardingPayload(String json, String fingerprint) {
    public OnboardingPayload {
        if (json == null || json.isBlank() || fingerprint == null
                || !fingerprint.matches("^[0-9a-f]{64}$")) {
            throw new IllegalArgumentException("onboarding_payload_invalid");
        }
    }

    @Override public String toString() { return "OnboardingPayload[redacted]"; }
}
