package dev.distracted.iam.messaging;

public record OnboardingIntent(String eventId, String activationId, long onboardingVersion, boolean created) {
    public OnboardingIntent {
        if (eventId == null || !eventId.matches("^evt_[A-Za-z0-9_-]{16,128}$")
                || activationId == null || onboardingVersion < 1) {
            throw new IllegalArgumentException("onboarding_intent_invalid");
        }
    }

    @Override public String toString() { return "OnboardingIntent[created=" + created + ",redacted]"; }
}
