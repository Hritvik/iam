package dev.distracted.iam.authorization;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

public final class AuthorizationCodeRedemption {
    private final AuthorizationCodeConsumptionRepository repository;
    private final AuthorizationCodeDigestCapability digestCapability;
    private final String issuer;

    public AuthorizationCodeRedemption(AuthorizationCodeConsumptionRepository repository,
            AuthorizationCodeDigestCapability digestCapability, String issuer) {
        this.repository = java.util.Objects.requireNonNull(repository);
        this.digestCapability = java.util.Objects.requireNonNull(digestCapability);
        if (issuer == null || issuer.isBlank()) throw new IllegalArgumentException("issuer_required");
        this.issuer = issuer;
    }

    public Optional<ConsumedAuthorization> redeem(AuthorizationCodeRedemptionCommand command) {
        if (command == null || !"authorization_code".equals(command.grantType())
                || command.clientId() == null || !command.clientId().matches("[a-z][a-z0-9-]{2,63}")
                || command.redirectUri() == null || command.redirectUri().length() > 512
                || command.correlationId() == null
                || !command.correlationId().matches("^cor_[A-Za-z0-9_-]{16,128}$")
                || !validVerifier(command.codeVerifier())) return Optional.empty();
        var material = parse(command.code());
        if (material.isEmpty()) return Optional.empty();
        var protection = repository.findProtection(material.get().codeId());
        if (protection.isEmpty() || !digestCapability.matches(material.get().codeId(), material.get().randomValue(),
                protection.get().keyVersion(), protection.get().digest())) return Optional.empty();
        return repository.consume(new AuthorizationCodeConsumption(material.get().codeId(), protection.get().digest(),
                protection.get().keyVersion(), issuer, command.clientId(), command.redirectUri(),
                sha256(command.codeVerifier()), protection.get().version(), command.correlationId()));
    }

    private static Optional<AuthorizationCodeMaterial> parse(String code) {
        if (code == null) return Optional.empty();
        var separator = code.indexOf('.');
        if (separator < 0 || separator != code.lastIndexOf('.')) return Optional.empty();
        var id = code.substring(0, separator);
        var encoded = code.substring(separator + 1);
        if (!id.matches("^acd_[A-Za-z0-9_-]{22,128}$") || !encoded.matches("^[A-Za-z0-9_-]{43}$")) {
            return Optional.empty();
        }
        try {
            var randomValue = Base64.getUrlDecoder().decode(encoded);
            return randomValue.length == 32 ? Optional.of(new AuthorizationCodeMaterial(id, randomValue)) : Optional.empty();
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private static boolean validVerifier(String verifier) {
        return verifier != null && verifier.length() >= 43 && verifier.length() <= 128
                && verifier.matches("[A-Za-z0-9._~-]+");
    }

    private static byte[] sha256(String verifier) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("sha256_unavailable");
        }
    }
}
