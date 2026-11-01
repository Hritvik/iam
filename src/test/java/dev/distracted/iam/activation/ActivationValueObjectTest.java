package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class ActivationValueObjectTest {
    @Test void activationRejectsMalformedIdsAndIncoherentState() {
        assertThatThrownBy(() -> new AppActivation("bad", ActivationState.ACTIVE, 1, 1, "FIRST_ACTIVATION"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppActivation("act_012345678901234567", ActivationState.ACTIVE, 1, 0, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppActivation("act_012345678901234567",
                ActivationState.PENDING_PREREQUISITES, 1, 1, "FIRST_ACTIVATION"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void prerequisitesRequireSatisfiedAndMissingToAgree() {
        assertThatThrownBy(() -> new ActivationPrerequisites(true, java.util.Set.of("verified_identifier")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(new ActivationPrerequisites(false, java.util.Set.of("verified_identifier")).satisfied()).isFalse();
    }

    @Test void transitionsCarryAnActivationOnlyForNonTerminalOutcomes() {
        assertThatThrownBy(() -> new ActivationTransition(ActivationTransition.Outcome.CONFLICT,
                Optional.of(new AppActivation("act_012345678901234567",
                        ActivationState.PENDING_PREREQUISITES, 1, 0, null))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ActivationTransition(ActivationTransition.Outcome.CREATED, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void firstActivationTransactionRejectsAnUnknownEnvironment() {
        assertThatThrownBy(() -> new FirstActivationTransaction(null, null, null, null, null, null, "qa"))
                .isInstanceOf(RuntimeException.class);
    }
}
