package dev.distracted.iam.messaging.adapter.jdbc;

import dev.distracted.iam.messaging.OnboardingIntent;
import dev.distracted.iam.messaging.OnboardingIntentCommand;
import dev.distracted.iam.messaging.OnboardingIntentException;
import dev.distracted.iam.messaging.OnboardingIntentWriter;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcOnboardingIntentWriter implements OnboardingIntentWriter {
    private final JdbcTemplate jdbc;

    public JdbcOnboardingIntentWriter(JdbcTemplate jdbc) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc);
    }

    @Override public OnboardingIntent append(OnboardingIntentCommand command) {
        try {
            if (!canonicalFingerprint(command.payloadJson()).equals(command.fingerprint())) {
                throw new OnboardingIntentException();
            }
            return jdbc.queryForObject("select * from append_onboarding_intent(?,?,?,?,?,?,?,?,?,?,?)",
                    (row, index) -> {
                        var result = row.getString("result");
                        if (!"CREATED".equals(result) && !"EXISTING".equals(result)) {
                            throw new OnboardingIntentException();
                        }
                        return new OnboardingIntent(row.getString("event_id"), command.activationId(),
                                command.onboardingVersion(), "CREATED".equals(result));
                    },
                    command.eventId(), command.activationId(), command.appRegistrationId(),
                    command.appSubject(), command.activationVersion(), command.onboardingVersion(),
                    command.onboardingReason(), command.environment(), command.correlationId(),
                    command.payloadJson(), command.fingerprint());
        } catch (DataAccessException exception) {
            throw new OnboardingIntentException(exception);
        }
    }

    private static String canonicalFingerprint(String payloadJson) {
        try {
            var canonical = new org.erdtman.jcs.JsonCanonicalizer(payloadJson).getEncodedUTF8();
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(canonical));
        } catch (java.io.IOException exception) {
            throw new OnboardingIntentException(exception);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("sha256_unavailable");
        }
    }
}
