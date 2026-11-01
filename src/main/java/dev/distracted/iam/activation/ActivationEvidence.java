package dev.distracted.iam.activation;

import java.util.Set;

public record ActivationEvidence(boolean verifiedIdentifier, boolean usableFactor, boolean recoveryPath,
                                 boolean appSubjectPresent, Set<String> requiredEvidence) {
    public ActivationEvidence {
        requiredEvidence = requiredEvidence == null ? Set.of() : Set.copyOf(requiredEvidence);
    }
}
