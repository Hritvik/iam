package dev.distracted.iam.messaging;

import java.util.Set;

public final class OnboardingEventFactory {
    private static final Set<String> REASONS = Set.of("FIRST_ACTIVATION", "RECONCILIATION");

    public OnboardingPayload create(String appRegistrationId, String appSubject, String activationId,
                                    long activationVersion, long onboardingVersion, String onboardingReason) {
        if (appRegistrationId == null || !appRegistrationId.matches("^[a-z][a-z0-9-]{2,63}$")
                || appSubject == null || !appSubject.matches("^aps_[A-Za-z0-9_-]{22,128}$")
                || activationId == null || activationVersion < 1 || onboardingVersion < 1
                || !REASONS.contains(onboardingReason)) {
            throw new OnboardingIntentException();
        }
        var payload = new OnboardingReadyPayload(appRegistrationId, appSubject, activationId,
                activationVersion, onboardingReason, onboardingVersion);
        return new OnboardingPayload(payload.canonicalizationInput(),
                new Rfc8785PayloadFingerprint().fingerprint(payload));
    }
}
