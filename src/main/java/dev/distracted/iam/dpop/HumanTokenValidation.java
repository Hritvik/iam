package dev.distracted.iam.dpop;

import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.token.VerifiedHumanAccessToken;

@FunctionalInterface
public interface HumanTokenValidation {
    VerifiedHumanAccessToken verify(String compact, RegistrationManifest registration, int securityVersion);
}
