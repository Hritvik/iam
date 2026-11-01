package dev.distracted.iam.authorization;

public record AuthorizationCodeConsumption(
        String codeId, byte[] codeDigest, short keyVersion, String issuer, String clientId,
        String redirectUri, byte[] calculatedChallenge, long expectedVersion, String correlationId) {
    public AuthorizationCodeConsumption {
        codeDigest = codeDigest.clone();
        calculatedChallenge = calculatedChallenge.clone();
    }
    @Override public byte[] codeDigest() { return codeDigest.clone(); }
    @Override public byte[] calculatedChallenge() { return calculatedChallenge.clone(); }
}
