package dev.distracted.iam.dpop;

import dev.distracted.iam.registration.RegistrationManifest;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public final class DpopProtectedRequestVerifier {
    private final HumanTokenValidation tokens;
    private final DpopProofValidation proofs;
    private final DpopStateDigestCapability digests;
    private final DpopStateStore state;
    private final SecureDpopNonceGenerator nonces;
    private final int nonceLifetime;
    private final int replayRetention;
    public DpopProtectedRequestVerifier(HumanTokenValidation tokens, DpopProofValidation proofs,
            DpopStateDigestCapability digests, DpopStateStore state, int replayRetention) {
        this(tokens, proofs, digests, state, new SecureDpopNonceGenerator(), 120, replayRetention);
    }
    public DpopProtectedRequestVerifier(HumanTokenValidation tokens, DpopProofValidation proofs,
            DpopStateDigestCapability digests, DpopStateStore state, SecureDpopNonceGenerator nonces,
            int nonceLifetime, int replayRetention) {
        this.tokens = java.util.Objects.requireNonNull(tokens);
        this.proofs = java.util.Objects.requireNonNull(proofs);
        this.digests = java.util.Objects.requireNonNull(digests);
        this.state = java.util.Objects.requireNonNull(state);
        this.nonces = java.util.Objects.requireNonNull(nonces);
        if (nonceLifetime < 30 || nonceLifetime > 300) {
            throw new IllegalArgumentException("dpop_nonce_lifetime_invalid");
        }
        this.nonceLifetime = nonceLifetime;
        if (replayRetention < 120 || replayRetention > 600) {
            throw new IllegalArgumentException("dpop_replay_retention_invalid");
        }
        this.replayRetention = replayRetention;
    }
    public String challenge(String compactToken, String compactProof, String method, String target,
            RegistrationManifest registration, int securityVersion, String correlationId) {
        var token = tokens.verify(compactToken, registration, securityVersion);
        var proof = proofs.verifyResourceChallengeProof(compactProof, method, target, compactToken,
                token.dpopKeyThumbprint().value());
        var material = nonces.next();
        var binding = token.appRegistrationId() + "|" + token.clientId();
        var challenge = new DpopChallengeState(material.nonceId(), protect(DpopStatePurpose.NONCE, binding,
                material.rawNonce()), protectReadable(DpopStatePurpose.REPLAY, replayBinding(proof), proof.jti()),
                protectReadable(DpopStatePurpose.THUMBPRINT, binding, proof.keyThumbprint()),
                protectReadable(DpopStatePurpose.TARGET, binding, proof.target()), token.appRegistrationId(), token.clientId(),
                proof.method(), nonceLifetime, replayRetention, correlationId);
        if (!state.issueResourceChallenge(challenge)) throw new DpopProofRejectedException();
        return material.rawNonce();
    }
    public VerifiedDpopPrincipal verify(String compactToken, String compactProof, String method, String target,
            String nonce, RegistrationManifest registration, int securityVersion) {
        return verify(compactToken, compactProof, method, target, nonce, registration, securityVersion,
                "cor_" + java.util.UUID.randomUUID().toString().replace("-", ""));
    }
    public VerifiedDpopPrincipal verify(String compactToken, String compactProof, String method, String target,
            String nonce, RegistrationManifest registration, int securityVersion, String correlationId) {
        var token = tokens.verify(compactToken, registration, securityVersion);
        var proof = proofs.verifyResourceProof(compactProof, method, target, nonce, compactToken,
                token.dpopKeyThumbprint().value());
        var binding = token.appRegistrationId() + "|" + token.clientId();
        var persisted = new DpopIssuanceState(protectReadable(DpopStatePurpose.NONCE, binding, nonce),
                protectReadable(DpopStatePurpose.REPLAY, replayBinding(proof), proof.jti()),
                protectReadable(DpopStatePurpose.THUMBPRINT, binding, proof.keyThumbprint()),
                protectReadable(DpopStatePurpose.TARGET, binding, proof.target()), token.appRegistrationId(),
                token.clientId(), proof.method(), replayRetention, correlationId);
        if (!state.consumeResource(persisted)) throw new DpopProofRejectedException();
        return new VerifiedDpopPrincipal(token.subject().value(), token.appRegistrationId(), token.clientId(),
                token.audience(), Set.of(token.scope().split(" ")), token.securityVersion());
    }

    private ProtectedDpopState protect(DpopStatePurpose purpose, String binding, String value) {
        return digests.protect(purpose, binding, value.getBytes(StandardCharsets.US_ASCII));
    }
    private ProtectedDpopCandidates protectReadable(DpopStatePurpose purpose, String binding, String value) {
        return digests.protectReadable(purpose, binding, value.getBytes(StandardCharsets.US_ASCII));
    }
    private static String replayBinding(VerifiedDpopProof proof) {
        return "RESOURCE|" + proof.keyThumbprint() + "|" + proof.method() + "|" + proof.target();
    }
}
