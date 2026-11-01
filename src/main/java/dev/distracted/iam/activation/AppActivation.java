package dev.distracted.iam.activation;

public record AppActivation(String activationId, ActivationState state, long activationVersion,
                            long onboardingVersion, String onboardingReason) {
    public AppActivation {
        if (activationId == null || !activationId.matches("^act_[A-Za-z0-9_-]{16,128}$")
                || state == null || activationVersion < 1 || onboardingVersion < 0) {
            throw new IllegalArgumentException("app_activation_invalid");
        }
        if ((state == ActivationState.ACTIVE) != (onboardingVersion >= 1 && onboardingReason != null)) {
            throw new IllegalArgumentException("app_activation_incoherent");
        }
    }
}
