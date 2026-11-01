package dev.distracted.iam.authorization;

public record AuthorizationCodeRedemptionCommand(
        String grantType, String code, String clientId, String redirectUri, String codeVerifier, String correlationId) {
    @Override public String toString() { return "AuthorizationCodeRedemptionCommand[clientId=" + clientId + ",protected]"; }
}
