package dev.distracted.iam.messaging;

import java.util.regex.Pattern;

public record OnboardingReadyPayload(String appRegistrationId, String appSubject, String activationId,
        long activationVersion, String onboardingReason, long onboardingVersion) implements EventPayload {
    private static final Pattern APP = Pattern.compile("^[a-z][a-z0-9-]{2,63}$");
    private static final Pattern SUBJECT = Pattern.compile("^aps_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern ACTIVATION = Pattern.compile("^act_[A-Za-z0-9_-]{16,128}$");

    public OnboardingReadyPayload {
        require(APP, appRegistrationId, "app registration");
        require(SUBJECT, appSubject, "app subject");
        require(ACTIVATION, activationId, "activation");
        if (activationVersion < 1 || onboardingVersion < 1) {
            throw new IllegalArgumentException("versions must be positive");
        }
        if (!"FIRST_ACTIVATION".equals(onboardingReason) && !"RECONCILIATION".equals(onboardingReason)) {
            throw new IllegalArgumentException("onboarding reason is not registered");
        }
    }

    @Override
    public String canonicalizationInput() {
        return "{\"activationId\":\"" + activationId + "\",\"activationState\":\"ACTIVE\","
                + "\"activationVersion\":" + activationVersion + ",\"appRegistrationId\":\""
                + appRegistrationId + "\",\"appSubject\":\"" + appSubject + "\","
                + "\"onboardingReason\":\"" + onboardingReason + "\",\"onboardingVersion\":"
                + onboardingVersion + ",\"requiredProfileState\":\"PROFILE_REQUIRED\"}";
    }

    private static void require(Pattern pattern, String value, String field) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }
}
