package dev.distracted.iam.authorization;

import dev.distracted.iam.registration.RegistrationRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;

public final class AuthorizationRequestService {
    private final RegistrationRegistry registry;
    private final AuthorizationRequestValidator validator;
    private final AuthorizationCodeRepository repository;
    private final AuthorizationCodeDigestCapability digestCapability;
    private final AuthorizationCodeMaterialGenerator materialGenerator;
    private final Duration lifetime;

    public AuthorizationRequestService(RegistrationRegistry registry, AuthorizationRequestValidator validator,
            AuthorizationCodeRepository repository, AuthorizationCodeDigestCapability digestCapability,
            AuthorizationCodeMaterialGenerator materialGenerator, Duration lifetime) {
        this.registry = Objects.requireNonNull(registry);
        this.validator = Objects.requireNonNull(validator);
        this.repository = Objects.requireNonNull(repository);
        this.digestCapability = Objects.requireNonNull(digestCapability);
        this.materialGenerator = Objects.requireNonNull(materialGenerator);
        if (lifetime == null || lifetime.compareTo(Duration.ofSeconds(60)) < 0
                || lifetime.compareTo(Duration.ofSeconds(300)) > 0) {
            throw new IllegalArgumentException("authorization_code_lifetime_invalid");
        }
        this.lifetime = lifetime;
    }

    public AuthorizationRedirectResult authorize(AuthenticatedIdentity principal,
            AuthorizationRequestCommand command, String correlationId) {
        Objects.requireNonNull(principal, "principal");
        if (command == null || correlationId == null
                || !correlationId.matches("^cor_[A-Za-z0-9_-]{16,128}$")) {
            throw new AuthorizationRequestRejectedException();
        }
        var registration = registry.findByClientId(command.clientId())
                .orElseThrow(AuthorizationRequestRejectedException::new);
        var accepted = validator.validate(command, registration);
        var material = materialGenerator.generate();
        var protectedCode = digestCapability.protect(material.codeId(), material.randomValue());
        var requestId = "arq_" + material.codeId().substring(4);
        var receipt = repository.issue(new AuthorizationCodeIssue(requestId, material.codeId(), accepted.issuer(),
                registration.appRegistrationId(), registration.client().clientId(),
                registration.resource().resourceId(), registration.resource().audience(),
                principal.identity().identityId(), accepted.redirectUri(), accepted.scope(),
                sha256(accepted.state()), sha256(accepted.nonce()), accepted.codeChallenge(),
                protectedCode.digest(), protectedCode.keyVersion(), lifetime, correlationId));
        return new AuthorizationRedirectResult(accepted.redirectUri(),
                material.codeId() + "." + SecureAuthorizationCodeMaterialGenerator.encode(material.randomValue()),
                accepted.state(), receipt.issuedAt(), receipt.expiresAt());
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("sha256_unavailable");
        }
    }
}
