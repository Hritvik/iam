package dev.distracted.iam.dpop.adapter.jdbc;

import dev.distracted.iam.dpop.DpopChallengeState;
import dev.distracted.iam.dpop.DpopIssuanceState;
import dev.distracted.iam.dpop.DpopStateStore;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcDpopStateStore implements DpopStateStore {
    private final JdbcTemplate jdbc;
    public JdbcDpopStateStore(JdbcTemplate jdbc) { this.jdbc = java.util.Objects.requireNonNull(jdbc); }

    @Override public boolean issueChallenge(DpopChallengeState value) {
        return issue(value, "TOKEN");
    }

    @Override public boolean issueResourceChallenge(DpopChallengeState value) {
        return issue(value, "RESOURCE");
    }

    private boolean issue(DpopChallengeState value, String purpose) {
        try {
            var result = jdbc.queryForObject(
                    "select result from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    String.class, value.nonceId(), value.nonce().digest(), value.nonce().keyVersion(), purpose,
                    value.appRegistrationId(), value.clientId(), newest(value.thumbprint().digests()), value.method(),
                    newest(value.target().digests()), value.replay().digests(), value.replay().versions(),
                    value.replayRetentionSeconds(), value.nonceLifetimeSeconds(), value.correlationId(),
                    value.thumbprint().digests(), value.target().digests());
            return "ISSUED".equals(result);
        } catch (DataAccessException exception) {
            throw new IllegalStateException("dpop_state_unavailable");
        }
    }

    private static byte[] newest(byte[][] digests) { return digests[digests.length - 1]; }

    @Override public boolean consumeForIssuance(DpopIssuanceState value) {
        return consume(value, "TOKEN");
    }

    @Override public boolean consumeResource(DpopIssuanceState value) {
        return consume(value, "RESOURCE");
    }

    private boolean consume(DpopIssuanceState value, String purpose) {
        try {
            var result = jdbc.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)",
                    String.class, value.nonce().digests(), value.nonce().versions(), purpose,
                    value.appRegistrationId(), value.clientId(), value.thumbprint().digests(), value.method(),
                    value.target().digests(), value.replay().digests(), value.replay().versions(),
                    value.replayRetentionSeconds(), value.correlationId());
            return "CONSUMED".equals(result);
        } catch (DataAccessException exception) {
            throw new IllegalStateException("dpop_state_unavailable");
        }
    }

    @Override public boolean claimResourceReplay(dev.distracted.iam.dpop.ProtectedDpopCandidates replay,
                                                  int retentionSeconds) {
        try {
            return Boolean.TRUE.equals(jdbc.queryForObject("select claim_dpop_resource_replay(?,?,?)",
                    Boolean.class, replay.digests(), replay.versions(), retentionSeconds));
        } catch (DataAccessException exception) {
            throw new IllegalStateException("dpop_state_unavailable");
        }
    }

    @Override public int activeSecurityVersion(String identity, String app, String client, String subject) {
        try {
            return jdbc.query("select * from read_active_token_security_context(?,?,?,?)", (row, number) -> {
                if (!"ACTIVE".equals(row.getString("result"))) throw new IllegalStateException("token_context_invalid");
                return Math.toIntExact(row.getLong("security_version"));
            }, identity, app, client, subject).stream().findFirst()
                    .orElseThrow(() -> new IllegalStateException("token_context_invalid"));
        } catch (DataAccessException | ArithmeticException exception) {
            throw new IllegalStateException("dpop_state_unavailable");
        }
    }

    @Override public void appendIssuanceAudit(String auditId, String codeId, String app, String client,
                                               String correlation) {
        try {
            if (!Boolean.TRUE.equals(jdbc.queryForObject("select append_token_issuance_audit(?,?,?,?,?)",
                    Boolean.class, auditId, codeId, app, client, correlation))) {
                throw new IllegalStateException("token_audit_unavailable");
            }
        } catch (DataAccessException exception) {
            throw new IllegalStateException("token_audit_unavailable");
        }
    }
}
