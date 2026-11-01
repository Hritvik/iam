package dev.distracted.iam.dpop;

import dev.distracted.iam.authorization.AuthorizationCodeRedemptionCommand;
import dev.distracted.iam.platform.persistence.TransactionRunner;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.token.DpopKeyThumbprint;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

public final class DefaultTokenEndpointOrchestrator implements TokenEndpointOrchestrator {
    private final java.util.function.Function<String, java.util.Optional<RegistrationManifest>> registrations;
    private final DpopProofValidation proofs;
    private final DpopStateDigestCapability digests;
    private final SecureDpopNonceGenerator nonces;
    private final DpopStateStore state;
    private final TokenAuthorizationRedeemer redemptions;
    private final TokenSubjectResolver subjects;
    private final TokenAccessIssuer tokens;
    private final TransactionRunner transactions;
    private final TokenEndpointRateLimiter limiter;
    private final String target;
    private final int nonceLifetime;
    private final int replayRetention;
    private final long tokenLifetime;

    public DefaultTokenEndpointOrchestrator(
            java.util.function.Function<String, java.util.Optional<RegistrationManifest>> registrations,
            DpopProofValidation proofs,
            DpopStateDigestCapability digests, SecureDpopNonceGenerator nonces, DpopStateStore state,
            TokenAuthorizationRedeemer redemptions, TokenSubjectResolver subjects, TokenAccessIssuer tokens,
            TransactionRunner transactions, TokenEndpointRateLimiter limiter, String target,
            Duration nonceLifetime, Duration replayRetention, Duration tokenLifetime) {
        this.registrations = java.util.Objects.requireNonNull(registrations);
        this.proofs = java.util.Objects.requireNonNull(proofs);
        this.digests = java.util.Objects.requireNonNull(digests);
        this.nonces = java.util.Objects.requireNonNull(nonces);
        this.state = java.util.Objects.requireNonNull(state);
        this.redemptions = java.util.Objects.requireNonNull(redemptions);
        this.subjects = java.util.Objects.requireNonNull(subjects);
        this.tokens = java.util.Objects.requireNonNull(tokens);
        this.transactions = java.util.Objects.requireNonNull(transactions);
        this.limiter = java.util.Objects.requireNonNull(limiter);
        this.target = requireTarget(target);
        this.nonceLifetime = seconds(nonceLifetime, 30, 300);
        this.replayRetention = seconds(replayRetention, 120, 600);
        this.tokenLifetime = seconds(tokenLifetime, 60, 900);
    }

    @Override public TokenEndpointOutcome exchange(TokenEndpointCommand command) {
        if (command == null || !"authorization_code".equals(command.grantType())) {
            throw new IllegalArgumentException("token_request_rejected");
        }
        if (!limiter.allow(rateLimit(command, TokenRateLimitCategory.CHALLENGE))) {
            throw new IllegalStateException("token_rate_limited");
        }
        var registration = registrations.apply(command.clientId())
                .filter(value -> value.securityPolicy().requireDpop()).orElseThrow(
                        () -> new IllegalArgumentException("token_request_rejected"));
        final VerifiedDpopProof proof;
        try {
            proof = proofs.verifyPresentedTokenProof(command.dpopProof(), "POST", target);
        } catch (DpopProofRejectedException exception) {
            var initial = proofs.verifyNonceChallengeProof(command.dpopProof(), "POST", target);
            return challenge(registration.appRegistrationId(), command, initial);
        }
        if (!limiter.allow(rateLimit(command, TokenRateLimitCategory.RETRY))) {
            throw new IllegalStateException("token_rate_limited");
        }
        var result = transactions.required(() -> issue(command, proof, registration));
        return result == null ? challenge(registration.appRegistrationId(), command, proof) : result;
    }

    private TokenEndpointOutcome issue(TokenEndpointCommand command, VerifiedDpopProof proof, RegistrationManifest registration) {
        var protectedState = issuanceState(command, proof);
        if (!state.consumeForIssuance(protectedState)) return null;
        var authorization = redemptions.redeem(new AuthorizationCodeRedemptionCommand(command.grantType(), command.code(),
                command.clientId(), command.redirectUri(), command.codeVerifier(), command.correlationId()))
                .orElseThrow(() -> new IllegalArgumentException("invalid_grant"));
        var subject = subjects.resolve(authorization, command.correlationId()).appSubject();
        var securityVersion = state.activeSecurityVersion(authorization.humanIdentityId(),
                authorization.appRegistrationId(), authorization.clientId(), subject.value());
        var compact = tokens.issue(authorization, subject, securityVersion,
                new DpopKeyThumbprint(proof.keyThumbprint()), command.correlationId(), registration);
        state.appendIssuanceAudit(auditId(), codeId(command.code()), authorization.appRegistrationId(),
                authorization.clientId(), command.correlationId());
        return new TokenEndpointOutcome.Success(compact, tokenLifetime, authorization.scope());
    }

    private TokenEndpointOutcome challenge(String appId, TokenEndpointCommand command, VerifiedDpopProof proof) {
        var material = nonces.next();
        var binding = appId + "|" + command.clientId();
        var challenge = new DpopChallengeState(material.nonceId(), protect(DpopStatePurpose.NONCE, binding, material.rawNonce()),
                protectReadable(DpopStatePurpose.REPLAY, replayBinding(proof), proof.jti()),
                protectReadable(DpopStatePurpose.THUMBPRINT, binding, proof.keyThumbprint()),
                protectReadable(DpopStatePurpose.TARGET, binding, proof.target()), appId, command.clientId(), proof.method(),
                nonceLifetime, replayRetention, command.correlationId());
        if (!transactions.required(() -> state.issueChallenge(challenge))) {
            throw new IllegalArgumentException("invalid_dpop_proof");
        }
        return new TokenEndpointOutcome.Challenge(material.rawNonce());
    }

    private DpopIssuanceState issuanceState(TokenEndpointCommand command, VerifiedDpopProof proof) {
        var app = registrations.apply(command.clientId()).orElseThrow().appRegistrationId();
        var binding = app + "|" + command.clientId();
        return new DpopIssuanceState(protectReadable(DpopStatePurpose.NONCE, binding, proof.nonce()),
                protectReadable(DpopStatePurpose.REPLAY, replayBinding(proof), proof.jti()),
                protectReadable(DpopStatePurpose.THUMBPRINT, binding, proof.keyThumbprint()),
                protectReadable(DpopStatePurpose.TARGET, binding, proof.target()), app, command.clientId(), proof.method(),
                replayRetention, command.correlationId());
    }

    private ProtectedDpopState protect(DpopStatePurpose purpose, String binding, String value) {
        return digests.protect(purpose, binding, value.getBytes(StandardCharsets.US_ASCII));
    }
    private ProtectedDpopCandidates protectReadable(DpopStatePurpose purpose, String binding, String value) {
        return digests.protectReadable(purpose, binding, value.getBytes(StandardCharsets.US_ASCII));
    }
    private TokenRateLimitRequest rateLimit(TokenEndpointCommand command, TokenRateLimitCategory category) {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        var client = protect(DpopStatePurpose.RATE_LIMIT, "TOKEN|CLIENT",
                "client-context:" + command.clientId());
        var network = protect(DpopStatePurpose.RATE_LIMIT, "TOKEN|NETWORK",
                "network-context:" + command.trustedNetworkContext());
        return new TokenRateLimitRequest(encoder.encodeToString(client.digest()),
                encoder.encodeToString(network.digest()), category);
    }
    private static String replayBinding(VerifiedDpopProof proof) {
        return "TOKEN|" + proof.keyThumbprint() + "|" + proof.method() + "|" + proof.target();
    }
    private static String codeId(String code) { return code.substring(0, code.indexOf('.')); }
    private static String auditId() {
        var bytes = new byte[16];
        new java.security.SecureRandom().nextBytes(bytes);
        return "aud_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private static int seconds(Duration value, int min, int max) {
        if (value == null || value.getNano() != 0 || value.toSeconds() < min || value.toSeconds() > max) {
            throw new IllegalArgumentException("token_duration_invalid");
        }
        return Math.toIntExact(value.toSeconds());
    }
    private static String requireTarget(String value) {
        if (value == null || !value.startsWith("https://") || value.length() > 512) {
            throw new IllegalArgumentException("token_target_invalid");
        }
        return value;
    }
}
