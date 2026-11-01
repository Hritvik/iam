package dev.distracted.iam.identity;

public final class IdentityEvidenceRejectedException extends RuntimeException {
    public IdentityEvidenceRejectedException() {
        super("identity_evidence_rejected");
    }
}
