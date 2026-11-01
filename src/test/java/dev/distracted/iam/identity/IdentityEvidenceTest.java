package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import dev.distracted.iam.messaging.CorrelationId;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class IdentityEvidenceTest {
    @Test
    void acceptsOnlyOutcomeConsistentOpaqueEvidence() {
        assertThat(new IdentityEvidence(EvidenceOutcome.CREATED, "fac_abcdefghijklmnopqrstuv", 2, 2).toString())
                .isEqualTo("IdentityEvidence[outcome=CREATED]");
        assertThat(new IdentityEvidence(EvidenceOutcome.EXISTING, "rcv_abcdefghijklmnopqrstuv", 2, 2).outcome())
                .isEqualTo(EvidenceOutcome.EXISTING);
        assertThat(new IdentityEvidence(EvidenceOutcome.REJECTED, null, 0, 0).evidenceId()).isNull();
        assertThat(new IdentityEvidence(EvidenceOutcome.CONFLICT, null, 2, 2).evidenceId()).isNull();
    }

    @Test
    void rejectsMalformedOrContradictoryEvidence() {
        assertThatThrownBy(() -> new IdentityEvidence(null, null, 0, 0))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("identity_evidence_invalid");
        assertThatThrownBy(() -> new IdentityEvidence(EvidenceOutcome.CREATED, "fac_short", 1, 1))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("identity_evidence_invalid");
        assertThatThrownBy(() -> new IdentityEvidence(EvidenceOutcome.REJECTED,
                "fac_abcdefghijklmnopqrstuv", 1, 1))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("identity_evidence_invalid");
        assertThatThrownBy(() -> new IdentityEvidence(EvidenceOutcome.CONFLICT, null, -1, 1))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("identity_evidence_invalid");
    }

    @Test
    void serviceRejectsInvalidCommandsBeforePersistence() {
        var service = new IdentityEvidenceService(mock(JdbcTemplate.class), new SecureEvidenceMaterialGenerator());
        var identity = new IdentityReference("hid_abcdefghijklmnopqrstuv");
        var correlation = new CorrelationId("cor_abcdefghijklmnop");
        assertThatThrownBy(() -> service.ensureEmailOtpFactor(null, 1, correlation))
                .isInstanceOf(IdentityEvidenceRejectedException.class).hasMessage("identity_evidence_rejected");
        assertThatThrownBy(() -> service.ensureEmailOtpFactor(identity, 0, correlation))
                .isInstanceOf(IdentityEvidenceRejectedException.class).hasMessage("identity_evidence_rejected");
        assertThatThrownBy(() -> service.ensureVerifiedEmailRecovery(identity, 1, null))
                .isInstanceOf(IdentityEvidenceRejectedException.class).hasMessage("identity_evidence_rejected");
        assertThatThrownBy(() -> service.currentIdentityVersion(null))
                .isInstanceOf(IdentityEvidenceRejectedException.class).hasMessage("identity_evidence_rejected");
    }
}
