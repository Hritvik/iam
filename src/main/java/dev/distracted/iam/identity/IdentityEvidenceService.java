package dev.distracted.iam.identity;

import dev.distracted.iam.messaging.CorrelationId;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class IdentityEvidenceService {
    private final JdbcTemplate jdbc;
    private final EvidenceMaterialGenerator materials;

    public IdentityEvidenceService(JdbcTemplate jdbc, EvidenceMaterialGenerator materials) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc, "jdbc");
        this.materials = java.util.Objects.requireNonNull(materials, "materials");
    }

    public IdentityEvidence ensureEmailOtpFactor(IdentityReference identity, long expectedVersion,
            CorrelationId correlationId) {
        return ensure("select * from ensure_email_otp_factor(?,?,?,?,?)", identity, expectedVersion,
                materials.factorId(), materials.auditId(), correlationId);
    }

    public IdentityEvidence ensureVerifiedEmailRecovery(IdentityReference identity, long expectedVersion,
            CorrelationId correlationId) {
        return ensure("select * from ensure_verified_email_recovery(?,?,?,?,?)", identity, expectedVersion,
                materials.recoveryMethodId(), materials.auditId(), correlationId);
    }

    public long currentIdentityVersion(IdentityReference identity) {
        requireIdentity(identity);
        var version = jdbc.queryForObject("select version from human_identity where identity_id=?", Long.class,
                identity.identityId());
        if (version == null) throw new IdentityEvidenceRejectedException();
        return version;
    }

    private IdentityEvidence ensure(String sql, IdentityReference identity, long expectedVersion, String evidenceId,
            String auditId, CorrelationId correlationId) {
        requireIdentity(identity);
        if (expectedVersion < 1 || correlationId == null) throw new IdentityEvidenceRejectedException();
        try {
            return jdbc.query(sql, (result, row) -> map(result), identity.identityId(), expectedVersion, evidenceId,
                    auditId, correlationId.value()).stream().findFirst().orElseThrow(IdentityEvidenceRejectedException::new);
        } catch (DataAccessException exception) {
            throw new IdentityEvidenceRejectedException();
        }
    }

    private static IdentityEvidence map(ResultSet result) throws SQLException {
        var outcome = EvidenceOutcome.valueOf(result.getString("outcome"));
        var identityVersion = result.getObject("identity_version") == null ? 0 : result.getLong("identity_version");
        var securityVersion = result.getObject("security_version") == null ? 0 : result.getLong("security_version");
        return new IdentityEvidence(outcome, result.getString("evidence_id"), identityVersion, securityVersion);
    }

    private static void requireIdentity(IdentityReference identity) {
        if (identity == null) throw new IdentityEvidenceRejectedException();
    }
}
