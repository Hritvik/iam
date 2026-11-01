package dev.distracted.iam.activation;

import java.util.Set;

public record ActivationPrerequisites(boolean satisfied, Set<String> missing) {
    public ActivationPrerequisites {
        missing = missing == null ? Set.of() : Set.copyOf(missing);
        if (satisfied != missing.isEmpty()) throw new IllegalArgumentException("activation_prerequisites_incoherent");
    }

    @Override public String toString() { return "ActivationPrerequisites[satisfied=" + satisfied + ",missing=" + missing + "]"; }
}
