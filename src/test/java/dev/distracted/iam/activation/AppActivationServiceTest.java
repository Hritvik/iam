package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AppActivationServiceTest {
    private static final String APP = "dutch-development";
    private static final String IDENTITY = "hid_0123456789012345678901";
    private static final String SUBJECT = "aps_0123456789012345678901ab";

    @Test void createsAPendingActivationWithoutOnboardingWhenPrerequisitesAreMissing() {
        var repository = new FakeRepository();
        repository.evidence = new ActivationEvidence(false, true, true, true,
                Set.of("verified_identifier", "usable_factor", "recovery_path"));
        repository.transitions.add(new ActivationTransition(ActivationTransition.Outcome.CREATED,
                Optional.of(new AppActivation("act_012345678901234567", ActivationState.PENDING_PREREQUISITES, 1, 0, null))));

        var activation = service(repository).advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345");

        assertThat(activation.state()).isEqualTo(ActivationState.PENDING_PREREQUISITES);
        assertThat(activation.onboardingVersion()).isZero();
        assertThat(service(repository).prerequisites(APP, IDENTITY).missing()).containsExactly("verified_identifier");
    }

    @Test void retriesOnAConcurrentVersionConflict() {
        var repository = new FakeRepository();
        repository.transitions.add(new ActivationTransition(ActivationTransition.Outcome.CONFLICT, Optional.empty()));
        repository.transitions.add(new ActivationTransition(ActivationTransition.Outcome.ACTIVATED,
                Optional.of(new AppActivation("act_012345678901234567", ActivationState.ACTIVE, 2, 1, "FIRST_ACTIVATION"))));

        var activation = service(repository).advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345");

        assertThat(activation.state()).isEqualTo(ActivationState.ACTIVE);
        assertThat(activation.onboardingVersion()).isEqualTo(1);
        assertThat(repository.attempts).isEqualTo(2);
    }

    @Test void returnsTheExistingActivationWithoutAnotherOnboardingVersion() {
        var repository = new FakeRepository();
        repository.existing = Optional.of(new AppActivation("act_012345678901234567", ActivationState.ACTIVE, 2, 1,
                "FIRST_ACTIVATION"));
        repository.transitions.add(new ActivationTransition(ActivationTransition.Outcome.EXISTING,
                Optional.of(repository.existing.orElseThrow())));

        var activation = service(repository).advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345");

        assertThat(activation.activationVersion()).isEqualTo(2);
        assertThat(activation.onboardingVersion()).isEqualTo(1);
        assertThat(repository.lastExpectedVersion).isEqualTo(2);
    }

    @Test void failsClosedAfterRepeatedConflictsOrARejectedTransition() {
        var conflicting = new FakeRepository();
        for (int attempt = 0; attempt < 4; attempt++) {
            conflicting.transitions.add(new ActivationTransition(ActivationTransition.Outcome.CONFLICT, Optional.empty()));
        }
        assertThatThrownBy(() -> service(conflicting).advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345"))
                .isInstanceOf(AppActivationException.class);

        var rejected = new FakeRepository();
        rejected.transitions.add(new ActivationTransition(ActivationTransition.Outcome.REJECTED, Optional.empty()));
        assertThatThrownBy(() -> service(rejected).advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345"))
                .isInstanceOf(AppActivationException.class);
    }

    private static AppActivationService service(AppActivationRepository repository) {
        return new AppActivationService(repository, () -> "act_012345678901234567",
                new ActivationPrerequisiteEvaluator());
    }

    private static final class FakeRepository implements AppActivationRepository {
        ActivationEvidence evidence = new ActivationEvidence(true, true, true, true, Set.of());
        Optional<AppActivation> existing = Optional.empty();
        final List<ActivationTransition> transitions = new ArrayList<>();
        int attempts;
        long lastExpectedVersion;
        private int next;

        @Override public Optional<AppActivation> find(String app, String identity) { return existing; }

        @Override public ActivationEvidence evidence(String app, String identity) { return evidence; }

        @Override public ActivationTransition transition(ActivationCommand command) {
            attempts++;
            lastExpectedVersion = command.expectedVersion();
            return transitions.get(Math.min(next++, transitions.size() - 1));
        }
    }
}
