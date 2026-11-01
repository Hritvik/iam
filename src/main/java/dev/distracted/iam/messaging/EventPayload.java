package dev.distracted.iam.messaging;

public sealed interface EventPayload permits OnboardingReadyPayload {
    String canonicalizationInput();
}
