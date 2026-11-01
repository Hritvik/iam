package dev.distracted.iam.messaging;

public interface OnboardingIntentWriter {
    OnboardingIntent append(OnboardingIntentCommand command);
}
