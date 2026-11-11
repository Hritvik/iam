package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.activation.AppSubjectResolution;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import dev.distracted.iam.authorization.refresh.RefreshFamilyIssue;
import dev.distracted.iam.authorization.refresh.RefreshFamilyView;
import dev.distracted.iam.authorization.refresh.RefreshIssueReceipt;
import dev.distracted.iam.authorization.refresh.RefreshRotationCommand;
import dev.distracted.iam.authorization.refresh.RefreshRotationOutcome;
import dev.distracted.iam.authorization.refresh.RefreshRotationResult;
import dev.distracted.iam.authorization.refresh.RefreshTokenRepository;
import java.security.SecureRandom;
import dev.distracted.iam.registration.RegistrationManifest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DefaultTokenEndpointOrchestratorTest {
    private static final String TARGET = "https://iam.example/oauth2/token";

    @Test void replayRetentionMustCoverProofAgePlusSkewAndMargin() {
        assertThat(DpopApplicationConfiguration.replayRetentionSeconds(Duration.ofSeconds(180), 120, 30))
                .isEqualTo(180);
        assertThatThrownBy(() -> DpopApplicationConfiguration.replayRetentionSeconds(
                Duration.ofSeconds(120), 120, 30))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("dpop_replay_retention_too_short");
        assertThatThrownBy(() -> DpopApplicationConfiguration.replayRetentionSeconds(
                Duration.ofSeconds(179), 120, 30))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void nonceChallengeCommitsWithoutInspectingTheAuthorizationCode() {
        var redemptions = new AtomicInteger();
        var state = new FakeState(false);
        var service = service(state, command -> {
            redemptions.incrementAndGet();
            return Optional.empty();
        });

        var outcome = service.exchange(command("initial-proof"));

        assertThat(outcome).isInstanceOf(TokenEndpointOutcome.Challenge.class);
        assertThat(redemptions).hasValue(0);
        assertThat(state.challenges).isEqualTo(1);
    }

    @Test void validNonceAndProofProduceOneDpopTokenInsideTheTransaction() {
        var state = new FakeState(true);
        var consumed = new ConsumedAuthorization("arq_abcdefghijklmnopqrstuv", "dutch-development", "dutch-mobile",
                "dutch-api", "https://api.dutch.example", "hid_abcdefghijklmnopqrstuv", "member:read",
                new byte[32], new byte[32]);
        var service = service(state, command -> Optional.of(consumed));

        var outcome = service.exchange(command("retry-proof"));

        assertThat(outcome).isEqualTo(new TokenEndpointOutcome.Success("header.claims.signature", 300, "member:read"));
        assertThat(state.audits).isEqualTo(1);
    }

    @Test void invalidStoredNonceChallengesWithoutRedeemingTheCode() {
        var redemptions = new AtomicInteger();
        var state = new FakeState(false);
        var service = service(state, command -> {
            redemptions.incrementAndGet();
            return Optional.empty();
        });

        assertThat(service.exchange(command("retry-proof"))).isInstanceOf(TokenEndpointOutcome.Challenge.class);
        assertThat(redemptions).hasValue(0);
        assertThat(state.challenges).isEqualTo(1);
    }

    @Test void consumedProofRollsBackWhenTheAuthorizationCodeIsInvalid() {
        var service = service(new FakeState(true), command -> Optional.empty());
        assertThatThrownBy(() -> service.exchange(command("retry-proof")))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("invalid_grant");
    }

    @Test void rejectsMissingAndUnsupportedRequestsBeforeProofOrDatabaseWork() {
        var service = service(new FakeState(true), command -> Optional.empty());
        assertThatThrownBy(() -> service.exchange(null)).isInstanceOf(IllegalArgumentException.class);
        var request = command("retry-proof");
        var unsupported = new TokenEndpointCommand("refresh_token", request.code(), request.redirectUri(),
                request.clientId(), request.codeVerifier(), request.dpopProof(), request.correlationId());
        assertThatThrownBy(() -> service.exchange(unsupported)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void authorizationCodeGrantAlsoIssuesARefreshFamily() {
        var repository = new FakeRefreshRepository();
        var service = serviceWithRefresh(new FakeState(true), command -> Optional.of(consumed()), repository);

        var outcome = (TokenEndpointOutcome.Success) service.exchange(command("retry-proof"));

        assertThat(outcome.refreshToken()).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(repository.issued).isNotNull();
        assertThat(repository.issued.scope()).isEqualTo("member:read");
    }

    @Test void refreshGrantRotatesAndReturnsANewAccessAndRefreshToken() {
        var repository = new FakeRefreshRepository();
        var service = serviceWithRefresh(new FakeState(true), command -> Optional.empty(), repository);

        var outcome = (TokenEndpointOutcome.Success) service.exchange(refreshCommand());

        assertThat(outcome.accessToken()).isEqualTo("header.claims.signature");
        assertThat(outcome.refreshToken()).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(repository.rotated).isNotNull();
        assertThat(repository.rotated.securityVersion()).isEqualTo(1);
    }

    private static ConsumedAuthorization consumed() {
        return new ConsumedAuthorization("arq_abcdefghijklmnopqrstuv", "dutch-development", "dutch-mobile",
                "dutch-api", "https://api.dutch.example", "hid_abcdefghijklmnopqrstuv", "member:read",
                new byte[32], new byte[32]);
    }

    private static TokenEndpointCommand refreshCommand() {
        return new TokenEndpointCommand("refresh_token", null, null, "dutch-mobile", null,
                "retry-proof", "cor_abcdefghijklmnop", "127.0.0.1", "a".repeat(43));
    }

    private static DefaultTokenEndpointOrchestrator serviceWithRefresh(FakeState state,
            TokenAuthorizationRedeemer redeemer, RefreshTokenRepository repository) {
        return new DefaultTokenEndpointOrchestrator(client -> Optional.of(registration()), proofVerifier(),
                new FixedDigest(), new SecureDpopNonceGenerator(), state, redeemer,
                (command, correlation) -> new AppSubjectResolution(new AppSubject("aps_abcdefghijklmnopqrstuvwx"),
                        AppSubjectResolution.Outcome.EXISTING),
                (command, subject, version, thumbprint, correlation, registration) -> "header.claims.signature",
                new dev.distracted.iam.platform.persistence.TransactionRunner() {
                    @Override public <T> T required(java.util.function.Supplier<T> work) { return work.get(); }
                }, client -> true, TARGET, Duration.ofSeconds(120), Duration.ofSeconds(180),
                Duration.ofSeconds(300), repository,
                new dev.distracted.iam.authorization.refresh.SecureRefreshTokenMaterialGenerator(new SecureRandom()),
                Duration.ofDays(30), Duration.ofDays(7));
    }

    private static DefaultTokenEndpointOrchestrator service(FakeState state,
            TokenAuthorizationRedeemer redeemer) {
        return new DefaultTokenEndpointOrchestrator(client -> Optional.of(registration()), proofVerifier(),
                new FixedDigest(), new SecureDpopNonceGenerator(), state, redeemer,
                (command, correlation) -> new AppSubjectResolution(new AppSubject("aps_abcdefghijklmnopqrstuvwx"),
                        AppSubjectResolution.Outcome.EXISTING),
                (command, subject, version, thumbprint, correlation, registration) -> "header.claims.signature",
                new dev.distracted.iam.platform.persistence.TransactionRunner() {
                    @Override public <T> T required(java.util.function.Supplier<T> work) { return work.get(); }
                }, client -> true, TARGET, Duration.ofSeconds(120), Duration.ofSeconds(180),
                Duration.ofSeconds(300));
    }

    private static TokenEndpointCommand command(String proof) {
        return new TokenEndpointCommand("authorization_code", "acd_abcdefghijklmnopqrstuv." + "a".repeat(43),
                "dutch://oauth/callback", "dutch-mobile", "v".repeat(43), proof,
                "cor_abcdefghijklmnop");
    }

    private static DpopProofValidation proofVerifier() {
        return new DpopProofValidation() {
            @Override public VerifiedDpopProof verifyNonceChallengeProof(String proof, String method, String target) {
                return verified(null);
            }
            @Override public VerifiedDpopProof verifyPresentedTokenProof(String proof, String method, String target) {
                if ("initial-proof".equals(proof)) throw new DpopProofRejectedException();
                return verified("n".repeat(43));
            }
            @Override public VerifiedDpopProof verifyResourceProof(String proof, String method, String target,
                    String nonce, String token, String thumbprint) { throw new UnsupportedOperationException(); }
            @Override public VerifiedDpopProof verifyResourceChallengeProof(String proof, String method,
                    String target, String token, String thumbprint) { throw new UnsupportedOperationException(); }
            private VerifiedDpopProof verified(String nonce) {
                return new VerifiedDpopProof("POST", TARGET, Instant.parse("2026-10-26T00:00:00Z"),
                        "proof_jti_abcdefghijklmnop", nonce, java.util.Base64.getUrlEncoder().withoutPadding()
                                .encodeToString(new byte[32]));
            }
        };
    }

    private static RegistrationManifest registration() {
        return new RegistrationManifest(1, "dutch-development", "Dutch", "development",
                new RegistrationManifest.Client("dutch-mobile", "public", List.of("dutch://oauth/callback"),
                        List.of("authorization_code"), List.of("S256"), "external"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.example", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"), List.of("verified_identifier")));
    }

    static class FixedDigest implements DpopStateDigestCapability {
        @Override public ProtectedDpopState protect(DpopStatePurpose purpose, String binding, byte[] value) { return new ProtectedDpopState((short) 1, new byte[32]); }
        @Override public ProtectedDpopCandidates protectReadable(DpopStatePurpose purpose, String binding,
                byte[] value) {
            return new ProtectedDpopCandidates(java.util.List.of(protect(purpose, binding, value)));
        }
        @Override public boolean matches(DpopStatePurpose purpose, String binding, byte[] value, short version, byte[] expected) { return true; }
        @Override public short keyVersion() { return 1; }
        @Override public java.util.Set<Short> readableKeyVersions() { return java.util.Set.of((short) 1); }
        @Override public java.util.Map<Short, String> keyReferences() { return java.util.Map.of((short) 1, "test"); }
        @Override public dev.distracted.iam.platform.crypto.CapabilityMetadata metadata() { return null; }
        @Override public dev.distracted.iam.platform.crypto.CapabilitySelfCheck selfCheck() { return dev.distracted.iam.platform.crypto.CapabilitySelfCheck.ready(); }
    }

    private static final class FakeState implements DpopStateStore {
        final boolean consumable;
        int challenges;
        int audits;
        FakeState(boolean consumable) { this.consumable = consumable; }
        @Override public boolean issueChallenge(DpopChallengeState value) {
            challenges++;
            return true;
        }
        @Override public boolean consumeForIssuance(DpopIssuanceState value) { return consumable; }
        @Override public boolean issueResourceChallenge(DpopChallengeState value) {
            throw new UnsupportedOperationException();
        }
        @Override public boolean consumeResource(DpopIssuanceState value) {
            throw new UnsupportedOperationException();
        }
        @Override public boolean claimResourceReplay(ProtectedDpopCandidates replay, int retention) {
            throw new UnsupportedOperationException();
        }
        @Override public int activeSecurityVersion(String identity, String app, String client, String subject) { return 1; }
        @Override public void appendIssuanceAudit(String auditId, String codeId, String app, String client,
                                                   String correlation) {
            audits++;
        }
    }

    private static final class FakeRefreshRepository implements RefreshTokenRepository {
        private static final String FAMILY = "rfm_" + "a".repeat(24);
        RefreshFamilyIssue issued;
        RefreshRotationCommand rotated;

        @Override public java.util.Optional<RefreshFamilyView> findByTokenDigest(byte[] digest) {
            return java.util.Optional.of(new RefreshFamilyView(FAMILY, "hid_abcdefghijklmnopqrstuv",
                    "dutch-development", "dutch-mobile", "dutch-api", "https://api.dutch.example",
                    "member:read", 1, "a".repeat(43), "ACTIVE"));
        }

        @Override public RefreshIssueReceipt issue(RefreshFamilyIssue issue) {
            issued = issue;
            var now = Instant.now();
            return new RefreshIssueReceipt(now, now.plusSeconds(604800), now.plusSeconds(2592000), 1);
        }

        @Override public RefreshRotationResult rotate(RefreshRotationCommand command) {
            rotated = command;
            var now = Instant.now();
            return new RefreshRotationResult(RefreshRotationOutcome.ROTATED, FAMILY, command.newTokenId(), 2,
                    now, now.plusSeconds(604800), "dutch-development", "dutch-mobile", "dutch-api",
                    "https://api.dutch.example", "hid_abcdefghijklmnopqrstuv", "member:read",
                    now.plusSeconds(2592000));
        }

        @Override public boolean revokeFamily(String familyId, String reason, String correlationId) {
            return true;
        }
    }
}
