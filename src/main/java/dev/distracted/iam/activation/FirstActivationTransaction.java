package dev.distracted.iam.activation;

import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.messaging.CorrelationId;
import dev.distracted.iam.messaging.OnboardingEventFactory;
import dev.distracted.iam.messaging.OnboardingIntentCommand;
import dev.distracted.iam.messaging.OnboardingIntentWriter;
import dev.distracted.iam.messaging.SecureOnboardingEventIdGenerator;
import dev.distracted.iam.platform.persistence.TransactionRunner;
import java.util.Objects;
import java.util.Optional;

public final class FirstActivationTransaction {
    private final AppSubjectResolver subjects;
    private final AppActivationService activations;
    private final OnboardingEventFactory events;
    private final OnboardingIntentWriter intents;
    private final SecureOnboardingEventIdGenerator eventIds;
    private final TransactionRunner transactions;
    private final String environment;

    public FirstActivationTransaction(AppSubjectResolver subjects, AppActivationService activations,
                                      OnboardingEventFactory events, OnboardingIntentWriter intents,
                                      SecureOnboardingEventIdGenerator eventIds, TransactionRunner transactions,
                                      String environment) {
        this.subjects = Objects.requireNonNull(subjects);
        this.activations = Objects.requireNonNull(activations);
        this.events = Objects.requireNonNull(events);
        this.intents = Objects.requireNonNull(intents);
        this.eventIds = Objects.requireNonNull(eventIds);
        this.transactions = Objects.requireNonNull(transactions);
        if (environment == null || !java.util.Set.of("development", "test", "staging", "production").contains(environment)) {
            throw new IllegalArgumentException("activation_environment_invalid");
        }
        this.environment = environment;
    }

    public FirstActivationResult activate(String appRegistrationId, String humanIdentityId, String correlationId) {
        return transactions.required(() -> {
            var resolution = subjects.resolve(new AppSubjectResolutionCommand(appRegistrationId,
                    new IdentityReference(humanIdentityId), new CorrelationId(correlationId)));
            var subject = resolution.appSubject().value();
            var activation = activations.advance(appRegistrationId, humanIdentityId, subject, correlationId);
            if (activation.state() != ActivationState.ACTIVE) {
                return new FirstActivationResult(activation, Optional.empty());
            }
            var payload = events.create(appRegistrationId, subject, activation.activationId(),
                    activation.activationVersion(), activation.onboardingVersion(), activation.onboardingReason());
            var intent = intents.append(new OnboardingIntentCommand(eventIds.next(), activation.activationId(),
                    appRegistrationId, subject, activation.activationVersion(), activation.onboardingVersion(),
                    activation.onboardingReason(), environment, correlationId, payload.json(), payload.fingerprint()));
            return new FirstActivationResult(activation, Optional.of(intent));
        });
    }
}
