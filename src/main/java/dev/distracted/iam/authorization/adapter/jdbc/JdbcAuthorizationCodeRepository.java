package dev.distracted.iam.authorization.adapter.jdbc;

import dev.distracted.iam.authorization.AuthorizationCodeIssue;
import dev.distracted.iam.authorization.AuthorizationCodeRepository;
import dev.distracted.iam.authorization.AuthorizationIssueReceipt;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcAuthorizationCodeRepository implements AuthorizationCodeRepository {
    private final JdbcTemplate jdbc;

    public JdbcAuthorizationCodeRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override public AuthorizationIssueReceipt issue(AuthorizationCodeIssue issue) {
        try {
            return jdbc.queryForObject(
                    "select * from issue_authorization_code(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (result, row) -> new AuthorizationIssueReceipt(
                            result.getTimestamp("issued_at").toInstant(),
                            result.getTimestamp("expires_at").toInstant(),
                            result.getLong("version")),
                    issue.authorizationRequestId(), issue.authorizationCodeId(), issue.issuer(),
                    issue.appRegistrationId(), issue.clientId(), issue.resourceId(), issue.resourceAudience(),
                    issue.humanIdentityId(), issue.redirectUri(), issue.scope(), issue.stateDigest(), issue.nonceDigest(),
                    issue.codeChallenge(), issue.codeDigest(), issue.digestKeyVersion(),
                    Math.toIntExact(issue.lifetime().toSeconds()), issue.correlationId());
        } catch (DataAccessException exception) {
            throw new IllegalStateException("authorization_issue_unavailable");
        }
    }
}
