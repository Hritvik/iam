package dev.distracted.iam.authorization;

public record AuthorizationRequestCommand(
        String clientId,
        String responseType,
        String redirectUri,
        String scope,
        String resource,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod) {
    @Override public String toString() { return "AuthorizationRequestCommand[protected]"; }
}
