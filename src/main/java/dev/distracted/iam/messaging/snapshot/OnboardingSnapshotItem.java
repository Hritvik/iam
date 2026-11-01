package dev.distracted.iam.messaging.snapshot;

public record OnboardingSnapshotItem(String appSubject, String activationId, String activationState,
                                     long activationVersion, String onboardingReason, long onboardingVersion,
                                     String requiredProfileState) {
    @Override public String toString() { return "OnboardingSnapshotItem[redacted]"; }
}
