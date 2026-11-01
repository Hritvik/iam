package dev.distracted.iam.dpop;

public final class DpopProofRejectedException extends RuntimeException {
    public DpopProofRejectedException() {
        super("invalid_dpop_proof");
    }
}
