package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.token.DpopKeyThumbprint;
import dev.distracted.iam.token.VerifiedHumanAccessToken;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class DpopProtectedRequestVerifierTest {
    @Test void returnsOnlyAnAppScopedPrincipalAfterDurableReplayClaim() {
        var state = new ResourceState(true);
        var service = new DpopProtectedRequestVerifier((token, registration, security) -> verifiedToken(),
                new Proofs(), new FixedDigest(), state, 180);

        var principal = service.verify("compact.token.value", "compact.proof.value", "GET",
                "https://api.dutch.example/member", "n".repeat(43), registration(), 1);

        assertThat(principal.appSubject()).isEqualTo("aps_abcdefghijklmnopqrstuvwx");
        assertThat(principal.toString()).doesNotContain("compact", "aps_");
        assertThat(state.claims).isEqualTo(1);
    }

    @Test void rejectsASequentialReplayWithoutReturningAPrincipal() {
        var service = new DpopProtectedRequestVerifier((token, registration, security) -> verifiedToken(),
                new Proofs(), new FixedDigest(), new ResourceState(false), 180);
        assertThatThrownBy(() -> service.verify("compact.token.value", "compact.proof.value", "GET",
                "https://api.dutch.example/member", "n".repeat(43), registration(), 1))
                .isInstanceOf(DpopProofRejectedException.class);
    }

    @Test void rejectsReplayRetentionOutsideTheDurableBound() {
        assertThatThrownBy(() -> new DpopProtectedRequestVerifier((token, registration, security) -> verifiedToken(),
                new Proofs(), new FixedDigest(), new ResourceState(true), 119))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopProtectedRequestVerifier((token, registration, security) -> verifiedToken(),
                new Proofs(), new FixedDigest(), new ResourceState(true), 601))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static VerifiedHumanAccessToken verifiedToken() {
        return new VerifiedHumanAccessToken(new AppSubject("aps_abcdefghijklmnopqrstuvwx"), "dutch-development",
                "dutch-mobile", "https://api.dutch.example", "member:read", 1,
                new DpopKeyThumbprint(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])),
                Instant.parse("2026-10-26T00:00:00Z"), Instant.parse("2026-10-26T00:05:00Z"));
    }
    private static RegistrationManifest registration() {
        return new RegistrationManifest(1, "dutch-development", "Dutch", "development",
                new RegistrationManifest.Client("dutch-mobile", "public", List.of("dutch://oauth/callback"),
                        List.of("authorization_code"), List.of("S256"), "external"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.example", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"), List.of("verified_identifier")));
    }
    private static final class Proofs implements DpopProofValidation {
        @Override public VerifiedDpopProof verifyNonceChallengeProof(String compact, String method, String target) { throw new UnsupportedOperationException(); }
        @Override public VerifiedDpopProof verifyPresentedTokenProof(String compact, String method, String target) { throw new UnsupportedOperationException(); }
        @Override public VerifiedDpopProof verifyResourceProof(String proof, String method, String target, String nonce,
                String token, String thumbprint) {
            return new VerifiedDpopProof(method, target, Instant.parse("2026-10-26T00:00:00Z"),
                    "resource_jti_abcdefghijkl", nonce, thumbprint);
        }
        @Override public VerifiedDpopProof verifyResourceChallengeProof(String proof, String method, String target,
                String token, String thumbprint) {
            return new VerifiedDpopProof(method, target, Instant.parse("2026-10-26T00:00:00Z"),
                    "resource_jti_challenge_abc", null, thumbprint);
        }
    }
    private static final class ResourceState extends FakeStateBase {
        final boolean winner;
        int claims;
        ResourceState(boolean winner) { this.winner = winner; }
        @Override public boolean claimResourceReplay(ProtectedDpopCandidates replay, int retention) {
            claims++;
            return winner;
        }
        @Override public boolean consumeResource(DpopIssuanceState state) {
            claims++;
            return winner;
        }
    }
    private abstract static class FakeStateBase implements DpopStateStore {
        @Override public boolean issueChallenge(DpopChallengeState state) { throw new UnsupportedOperationException(); }
        @Override public boolean issueResourceChallenge(DpopChallengeState state) { return true; }
        @Override public boolean consumeForIssuance(DpopIssuanceState state) { throw new UnsupportedOperationException(); }
        @Override public int activeSecurityVersion(String identity, String app, String client, String subject) { throw new UnsupportedOperationException(); }
        @Override public void appendIssuanceAudit(String audit, String code, String app, String client, String correlation) { throw new UnsupportedOperationException(); }
    }
    private static final class FixedDigest extends DefaultTokenEndpointOrchestratorTest.FixedDigest { }
}
