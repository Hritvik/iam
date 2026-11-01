package dev.distracted.iam.dpop;

public interface DpopStateStore {
    boolean issueChallenge(DpopChallengeState state);
    boolean issueResourceChallenge(DpopChallengeState state);
    boolean consumeForIssuance(DpopIssuanceState state);
    boolean consumeResource(DpopIssuanceState state);
    boolean claimResourceReplay(ProtectedDpopCandidates replay, int retentionSeconds);
    int activeSecurityVersion(String humanIdentityId, String appRegistrationId, String clientId, String appSubject);
    void appendIssuanceAudit(String auditId, String authorizationCodeId, String appRegistrationId,
                             String clientId, String correlationId);
}
