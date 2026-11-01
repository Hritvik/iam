package dev.distracted.iam.authorization;

public record ConsumedAuthorization(
        String authorizationRequestId, String appRegistrationId, String clientId, String resourceId,
        String resourceAudience, String humanIdentityId, String scope, byte[] stateDigest, byte[] nonceDigest) {
    public ConsumedAuthorization {
        stateDigest = stateDigest.clone();
        nonceDigest = nonceDigest.clone();
    }
    @Override public byte[] stateDigest() { return stateDigest.clone(); }
    @Override public byte[] nonceDigest() { return nonceDigest.clone(); }
}
