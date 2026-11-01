package dev.distracted.iam.registration;

import java.util.Optional;

public interface RegistrationRegistry {
    ReconciliationResult reconcile(ValidatedRegistration registration);
    Optional<RegistrationManifest> findByAppId(String appRegistrationId);
    Optional<RegistrationManifest> findByClientId(String clientId);
    Optional<RegistrationManifest> findByResourceId(String resourceId);
    Optional<RegistrationManifest> findByAudience(String audience);
    Optional<RegistrationManifest> findSoleRegistration();
}
