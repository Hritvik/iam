package dev.distracted.iam.activation;

import java.util.Optional;

public interface AppActivationRepository {
    Optional<AppActivation> find(String appRegistrationId, String humanIdentityId);
    ActivationEvidence evidence(String appRegistrationId, String humanIdentityId);
    ActivationTransition transition(ActivationCommand command);
}
