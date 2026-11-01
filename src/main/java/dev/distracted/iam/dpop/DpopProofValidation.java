package dev.distracted.iam.dpop;

public interface DpopProofValidation {
    VerifiedDpopProof verifyNonceChallengeProof(String compact, String method, String target);
    VerifiedDpopProof verifyPresentedTokenProof(String compact, String method, String target);
    VerifiedDpopProof verifyResourceProof(String compact, String method, String target, String nonce,
                                          String accessToken, String expectedKeyThumbprint);
    VerifiedDpopProof verifyResourceChallengeProof(String compact, String method, String target,
                                                   String accessToken, String expectedKeyThumbprint);
}
