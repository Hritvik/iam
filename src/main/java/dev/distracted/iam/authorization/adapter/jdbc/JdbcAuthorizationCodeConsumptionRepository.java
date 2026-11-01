package dev.distracted.iam.authorization.adapter.jdbc;

import dev.distracted.iam.authorization.AuthorizationCodeConsumption;
import dev.distracted.iam.authorization.AuthorizationCodeConsumptionRepository;
import dev.distracted.iam.authorization.AuthorizationCodeProtection;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcAuthorizationCodeConsumptionRepository implements AuthorizationCodeConsumptionRepository {
    private final JdbcTemplate jdbc;

    public JdbcAuthorizationCodeConsumptionRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override public Optional<AuthorizationCodeProtection> findProtection(String codeId) {
        try {
            return jdbc.query("select * from authorization_code_protection(?)",
                    (result, row) -> new AuthorizationCodeProtection(result.getShort("digest_key_version"),
                            result.getBytes("code_digest"), result.getLong("version")), codeId).stream().findFirst();
        } catch (DataAccessException exception) {
            return Optional.empty();
        }
    }

    @Override public Optional<ConsumedAuthorization> consume(AuthorizationCodeConsumption command) {
        try {
            return jdbc.query("select * from consume_authorization_code(?,?,?,?,?,?,?,?,?)", (result, row) -> {
                if (!"CONSUMED".equals(result.getString("result"))) return null;
                return new ConsumedAuthorization(result.getString("authorization_request_id"),
                        result.getString("app_registration_id"), result.getString("client_id"),
                        result.getString("resource_id"), result.getString("resource_audience"),
                        result.getString("human_identity_id"), result.getString("scope"),
                        result.getBytes("state_digest"), result.getBytes("nonce_digest"));
            }, command.codeId(), command.codeDigest(), command.keyVersion(), command.issuer(), command.clientId(),
                    command.redirectUri(), command.calculatedChallenge(), command.expectedVersion(),
                    command.correlationId()).stream().filter(java.util.Objects::nonNull).findFirst();
        } catch (DataAccessException exception) {
            return Optional.empty();
        }
    }
}
