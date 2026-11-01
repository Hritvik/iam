package dev.distracted.iam.activation;

import java.util.Objects;

public final class AppActivationService {
    private final AppActivationRepository repository;
    private final AppActivationMaterialGenerator materials;
    private final ActivationPrerequisiteEvaluator evaluator;

    public AppActivationService(AppActivationRepository repository, AppActivationMaterialGenerator materials,
                                ActivationPrerequisiteEvaluator evaluator) {
        this.repository = Objects.requireNonNull(repository);
        this.materials = Objects.requireNonNull(materials);
        this.evaluator = Objects.requireNonNull(evaluator);
    }

    public ActivationPrerequisites prerequisites(String appRegistrationId, String humanIdentityId) {
        return evaluator.evaluate(repository.evidence(appRegistrationId, humanIdentityId));
    }

    public AppActivation advance(String appRegistrationId, String humanIdentityId, String appSubject,
                                 String correlationId) {
        for (int attempt = 0; attempt < 3; attempt++) {
            var existing = repository.find(appRegistrationId, humanIdentityId);
            var activationId = existing.map(AppActivation::activationId).orElseGet(materials::nextActivationId);
            var expected = existing.map(AppActivation::activationVersion).orElse(0L);
            var transition = repository.transition(new ActivationCommand(activationId, appRegistrationId,
                    humanIdentityId, appSubject, expected, correlationId));
            if (transition.outcome() == ActivationTransition.Outcome.CONFLICT) continue;
            if (transition.outcome() == ActivationTransition.Outcome.REJECTED) {
                throw new AppActivationException();
            }
            return transition.activation().orElseThrow();
        }
        throw new AppActivationException();
    }
}
