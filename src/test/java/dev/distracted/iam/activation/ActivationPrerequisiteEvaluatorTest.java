package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
import org.junit.jupiter.api.Test;

class ActivationPrerequisiteEvaluatorTest {
    private final ActivationPrerequisiteEvaluator evaluator = new ActivationPrerequisiteEvaluator();
    private static final Set<String> REQUIRED = Set.of("verified_identifier", "usable_factor", "recovery_path");

    @Test void satisfiedOnlyWhenEveryRegisteredPrerequisiteAndTheSubjectExist() {
        var result = evaluator.evaluate(new ActivationEvidence(true, true, true, true, REQUIRED));
        assertThat(result.satisfied()).isTrue();
        assertThat(result.missing()).isEmpty();
    }

    @Test void reportsEachMissingPrerequisiteIndividually() {
        assertThat(evaluator.evaluate(new ActivationEvidence(false, true, true, true, REQUIRED)).missing())
                .containsExactly("verified_identifier");
        assertThat(evaluator.evaluate(new ActivationEvidence(true, false, true, true, REQUIRED)).missing())
                .containsExactly("usable_factor");
        assertThat(evaluator.evaluate(new ActivationEvidence(true, true, false, true, REQUIRED)).missing())
                .containsExactly("recovery_path");
        assertThat(evaluator.evaluate(new ActivationEvidence(true, true, true, false, REQUIRED)).missing())
                .containsExactly("app_subject");
        assertThat(evaluator.evaluate(new ActivationEvidence(false, false, false, true, REQUIRED)).missing())
                .containsExactlyInAnyOrder("verified_identifier", "usable_factor", "recovery_path");
    }

    @Test void anAppWithNoRegisteredEvidenceIsNotActivatable() {
        var result = evaluator.evaluate(new ActivationEvidence(true, true, true, true, Set.of()));
        assertThat(result.satisfied()).isFalse();
        assertThat(result.missing()).containsExactly("app_not_registered");
    }

    @Test void rejectsUnknownEvidenceTypesAndNullEvidence() {
        assertThatThrownBy(() -> evaluator.evaluate(new ActivationEvidence(true, true, true, true, Set.of("passkey"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("activation_evidence_invalid");
        assertThatThrownBy(() -> evaluator.evaluate(null)).isInstanceOf(IllegalArgumentException.class);
    }
}
