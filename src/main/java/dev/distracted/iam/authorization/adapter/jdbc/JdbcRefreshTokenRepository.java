package dev.distracted.iam.authorization.adapter.jdbc;

import dev.distracted.iam.authorization.refresh.RefreshFamilyIssue;
import dev.distracted.iam.authorization.refresh.RefreshFamilyView;
import dev.distracted.iam.authorization.refresh.RefreshIssueReceipt;
import dev.distracted.iam.authorization.refresh.RefreshRotationCommand;
import dev.distracted.iam.authorization.refresh.RefreshRotationOutcome;
import dev.distracted.iam.authorization.refresh.RefreshRotationResult;
import dev.distracted.iam.authorization.refresh.RefreshTokenException;
import dev.distracted.iam.authorization.refresh.RefreshTokenRepository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcRefreshTokenRepository implements RefreshTokenRepository {
    private final JdbcTemplate jdbc;

    public JdbcRefreshTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<RefreshFamilyView> findByTokenDigest(byte[] tokenDigest) {
        try {
            return jdbc.query("select * from refresh_family_for_token(?)",
                    (result, row) -> new RefreshFamilyView(result.getString("family_id"),
                            result.getString("human_identity_id"), result.getString("app_registration_id"),
                            result.getString("client_id"), result.getString("resource_id"),
                            result.getString("resource_audience"), result.getString("scope"),
                            result.getLong("security_version"), result.getString("dpop_jkt"),
                            result.getString("status")), tokenDigest).stream().findFirst();
        } catch (DataAccessException exception) {
            throw new RefreshTokenException("refresh_lookup_unavailable", exception);
        }
    }

    @Override
    public RefreshIssueReceipt issue(RefreshFamilyIssue issue) {
        try {
            return jdbc.queryForObject(
                    "select * from issue_refresh_family(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (result, row) -> new RefreshIssueReceipt(
                            instant(result, "issued_at"), instant(result, "expires_at"),
                            instant(result, "absolute_expires_at"), result.getLong("version")),
                    issue.familyId(), issue.tokenId(), issue.humanIdentityId(), issue.appRegistrationId(),
                    issue.clientId(), issue.resourceId(), issue.resourceAudience(), issue.scope(),
                    issue.dpopJkt(), issue.securityVersion(), issue.tokenDigest(),
                    Math.toIntExact(issue.absoluteLifetime().toSeconds()),
                    Math.toIntExact(issue.idleTimeout().toSeconds()), issue.correlationId());
        } catch (DataAccessException exception) {
            throw map(exception, "refresh_issue_rejected", "refresh_issue_unavailable");
        }
    }

    @Override
    public RefreshRotationResult rotate(RefreshRotationCommand command) {
        try {
            return jdbc.queryForObject(
                    "select * from rotate_refresh_token(?,?,?,?,?,?,?)",
                    (result, row) -> new RefreshRotationResult(
                            RefreshRotationOutcome.of(result.getString("result")),
                            result.getString("family_id"), result.getString("refresh_token_id"),
                            integer(result, "generation"), instant(result, "issued_at"),
                            instant(result, "expires_at"), result.getString("app_registration_id"),
                            result.getString("client_id"), result.getString("resource_id"),
                            result.getString("resource_audience"), result.getString("human_identity_id"),
                            result.getString("scope"), instant(result, "absolute_expires_at")),
                    command.presentedDigest(), command.newDigest(), command.dpopJkt(),
                    command.securityVersion(), command.newTokenId(), command.correlationId(),
                    Math.toIntExact(command.idleTimeout().toSeconds()));
        } catch (DataAccessException exception) {
            throw map(exception, "refresh_rotation_rejected", "refresh_rotation_unavailable");
        }
    }

    @Override
    public boolean revokeFamily(String familyId, String reason, String correlationId) {
        try {
            return Boolean.TRUE.equals(jdbc.queryForObject(
                    "select revoke_refresh_family(?,?,?)", Boolean.class, familyId, reason, correlationId));
        } catch (DataAccessException exception) {
            throw map(exception, "refresh_revocation_rejected", "refresh_revocation_unavailable");
        }
    }

    private static RefreshTokenException map(DataAccessException exception, String rejected, String unavailable) {
        var message = exception.getMostSpecificCause().getMessage();
        if (message != null && message.contains(rejected)) {
            return new RefreshTokenException(rejected, exception);
        }
        return new RefreshTokenException(unavailable, exception);
    }

    private static Instant instant(ResultSet result, String column) throws SQLException {
        var value = result.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static Integer integer(ResultSet result, String column) throws SQLException {
        var value = result.getObject(column);
        return value == null ? null : ((Number) value).intValue();
    }
}
