package dev.distracted.iam.messaging;

public final class OnboardingIntentException extends RuntimeException {
    public OnboardingIntentException() { super("onboarding_intent_rejected"); }
    public OnboardingIntentException(Throwable cause) { super("onboarding_intent_rejected", cause); }
}
