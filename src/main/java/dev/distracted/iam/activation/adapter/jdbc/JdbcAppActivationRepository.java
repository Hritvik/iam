package dev.distracted.iam.activation.adapter.jdbc;

import dev.distracted.iam.activation.ActivationCommand;
import dev.distracted.iam.activation.ActivationEvidence;
import dev.distracted.iam.activation.ActivationState;
import dev.distracted.iam.activation.ActivationTransition;
import dev.distracted.iam.activation.AppActivation;
import dev.distracted.iam.activation.AppActivationException;
import dev.distracted.iam.activation.AppActivationRepository;
import java.util.LinkedHashSet;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcAppActivationRepository implements AppActivationRepository {
    private final JdbcTemplate jdbc;

    public JdbcAppActivationRepository(JdbcTemplate jdbc) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc);
    }

    @Override public Optional<AppActivation> find(String appRegistrationId, String humanIdentityId) {
        try {
            return jdbc.query("select * from read_app_activation(?,?)", (row, index) -> map(row.getString("state"),
                    row.getString("activation_id"), row.getLong("activation_version"),
                    row.getLong("onboarding_version"), row.getString("onboarding_reason")),
                    appRegistrationId, humanIdentityId).stream().findFirst();
        } catch (DataAccessException exception) {
            throw new AppActivationException(exception);
        }
    }

    @Override public ActivationTransition transition(ActivationCommand command) {
        try {
            return jdbc.queryForObject("select * from advance_app_activation(?,?,?,?,?,?)",
                    (row, index) -> {
                        var outcome = row.getString("result");
                        var state = row.getString("state");
                        if (state == null) {
                            return new ActivationTransition(ActivationTransition.Outcome.valueOf(outcome), Optional.empty());
                        }
                        return new ActivationTransition(ActivationTransition.Outcome.valueOf(outcome),
                                Optional.of(map(state, row.getString("activation_id"),
                                        row.getLong("activation_version"), row.getLong("onboarding_version"),
                                        row.getString("onboarding_reason"))));
                    },
                    command.activationId(), command.appRegistrationId(), command.humanIdentityId(),
                    command.appSubject(), command.expectedVersion(), command.correlationId());
        } catch (DataAccessException exception) {
            throw new AppActivationException(exception);
        }
    }

    @Override public ActivationEvidence evidence(String appRegistrationId, String humanIdentityId) {
        try {
            return jdbc.queryForObject("select * from read_activation_evidence(?,?)",
                    (row, index) -> new ActivationEvidence(row.getBoolean("verified_identifier"),
                            row.getBoolean("usable_factor"), row.getBoolean("recovery_path"),
                            row.getBoolean("app_subject_present"),
                            new LinkedHashSet<>(java.util.Arrays.asList(
                                    (String[]) row.getArray("required_evidence").getArray()))),
                    appRegistrationId, humanIdentityId);
        } catch (DataAccessException exception) {
            throw new AppActivationException(exception);
        }
    }

    private static AppActivation map(String state, String activationId, long activationVersion,
                                     long onboardingVersion, String onboardingReason) {
        return new AppActivation(activationId, ActivationState.valueOf(state), activationVersion,
                onboardingVersion, onboardingReason);
    }
}
