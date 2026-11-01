package dev.distracted.iam.activation;

import dev.distracted.iam.messaging.OnboardingIntent;
import java.util.Optional;

public record FirstActivationResult(AppActivation activation, Optional<OnboardingIntent> onboardingIntent) {
    public FirstActivationResult {
        onboardingIntent = onboardingIntent == null ? Optional.empty() : onboardingIntent;
    }
}
