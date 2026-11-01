package dev.distracted.iam.activation;

import java.util.Optional;

public record ActivationTransition(Outcome outcome, Optional<AppActivation> activation) {
    public enum Outcome { CREATED, PENDING, ACTIVATED, EXISTING, CONFLICT, REJECTED }

    public ActivationTransition {
        activation = activation == null ? Optional.empty() : activation;
        if ((outcome == Outcome.CONFLICT || outcome == Outcome.REJECTED) && activation.isPresent()) {
            throw new IllegalArgumentException("activation_transition_invalid");
        }
        if ((outcome == Outcome.CREATED || outcome == Outcome.PENDING || outcome == Outcome.ACTIVATED
                || outcome == Outcome.EXISTING) && activation.isEmpty()) {
            throw new IllegalArgumentException("activation_transition_invalid");
        }
    }
}
