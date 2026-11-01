package dev.distracted.iam.messaging.snapshot;

public interface OnboardingSnapshotQuery {
    OnboardingSnapshotPage page(String appRegistrationId, String cursor, int limit);
}
