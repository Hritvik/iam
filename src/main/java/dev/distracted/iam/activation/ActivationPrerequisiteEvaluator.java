package dev.distracted.iam.activation;

import java.util.LinkedHashSet;
import java.util.Set;

public final class ActivationPrerequisiteEvaluator {
    private static final Set<String> KNOWN = Set.of("verified_identifier", "usable_factor", "recovery_path");

    public ActivationPrerequisites evaluate(ActivationEvidence evidence) {
        if (evidence == null || !KNOWN.containsAll(evidence.requiredEvidence())) {
            throw new IllegalArgumentException("activation_evidence_invalid");
        }
        var missing = new LinkedHashSet<String>();
        if (evidence.requiredEvidence().isEmpty()) missing.add("app_not_registered");
        if (evidence.requiredEvidence().contains("verified_identifier") && !evidence.verifiedIdentifier()) {
            missing.add("verified_identifier");
        }
        if (evidence.requiredEvidence().contains("usable_factor") && !evidence.usableFactor()) {
            missing.add("usable_factor");
        }
        if (evidence.requiredEvidence().contains("recovery_path") && !evidence.recoveryPath()) {
            missing.add("recovery_path");
        }
        if (!evidence.appSubjectPresent()) missing.add("app_subject");
        return new ActivationPrerequisites(missing.isEmpty(), missing);
    }
}
