package dev.distracted.iam.identity;

public record IdentityEvidence(EvidenceOutcome outcome, String evidenceId, long identityVersion,
        long securityVersion) {
    public IdentityEvidence {
        if (outcome == null || identityVersion < 0 || securityVersion < 0) {
            throw new IllegalArgumentException("identity_evidence_invalid");
        }
        if ((outcome == EvidenceOutcome.CREATED || outcome == EvidenceOutcome.EXISTING)
                && !validEvidenceId(evidenceId)) {
            throw new IllegalArgumentException("identity_evidence_invalid");
        }
        if ((outcome == EvidenceOutcome.REJECTED || outcome == EvidenceOutcome.CONFLICT) && evidenceId != null) {
            throw new IllegalArgumentException("identity_evidence_invalid");
        }
    }

    @Override
    public String toString() {
        return "IdentityEvidence[outcome=" + outcome + "]";
    }

    private static boolean validEvidenceId(String value) {
        return value != null && value.matches("^(fac_|rcv_)[A-Za-z0-9_-]{22,128}$");
    }
}
