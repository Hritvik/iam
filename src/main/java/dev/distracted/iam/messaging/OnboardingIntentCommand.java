package dev.distracted.iam.messaging;

public record OnboardingIntentCommand(String eventId, String activationId, String appRegistrationId,
                                      String appSubject, long activationVersion, long onboardingVersion,
                                      String onboardingReason, String environment, String correlationId,
                                      String payloadJson, String fingerprint) {
    public OnboardingIntentCommand {
        if (eventId == null || activationId == null || appRegistrationId == null || appSubject == null
                || onboardingReason == null || environment == null || correlationId == null
                || payloadJson == null || fingerprint == null) {
            throw new IllegalArgumentException("onboarding_intent_command_invalid");
        }
    }

    @Override public String toString() { return "OnboardingIntentCommand[redacted]"; }
}
