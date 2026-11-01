package dev.distracted.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import dev.distracted.iam.registration.ReconciliationResult;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.registration.RegistrationRegistry;
import dev.distracted.iam.registration.ValidatedRegistration;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class HumanAccessTokenIssuerTest {
    private static final String ISSUER = "https://iam.distracted.dev";
    private static final String THUMBPRINT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void aManifestCarryingCommandSignsWithoutReadingTheRegistryOrBindingVerifier() throws Exception {
        var key = key("signing01");
        var signer = new TestSigner(key, List.of(key.toPublicJWK()));
        var registry = org.mockito.Mockito.mock(dev.distracted.iam.registration.RegistrationRegistry.class);
        var issuer = new HumanAccessTokenIssuer(registry, (identity, app, candidate) -> {
            throw new AssertionError("binding verifier must not run for a composed command");
        }, signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC),
                ISSUER, () -> ISSUER, Duration.ofMinutes(5));

        var result = issuer.issue(new HumanAccessTokenIssueCommand(authorization(), registration(),
                new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA"), 7, new DpopKeyThumbprint(THUMBPRINT),
                "correlation-1"));

        assertThat(result.compactValue()).isNotBlank();
        org.mockito.Mockito.verifyNoInteractions(registry);
    }

    @Test
    void issuesExactClosedSenderConstrainedTokenFromCanonicalContext() throws Exception {
        var key = key("signing01");
        var signer = new TestSigner(key, List.of(key.toPublicJWK()));
        var authorization = authorization();
        var subject = new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        var issuer = new HumanAccessTokenIssuer(
                registry(registration()),
                (identity, app, candidate) -> identity.equals("hid_internal")
                        && app.equals("dutch-development") && candidate.equals(subject),
                signer,
                () -> "BBBBBBBBBBBBBBBBBBBBBB",
                Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC),
                ISSUER,
                () -> ISSUER,
                Duration.ofMinutes(5));

        var result = issuer.issue(new HumanAccessTokenIssueCommand(
                authorization, subject, 7, new DpopKeyThumbprint(THUMBPRINT), "correlation-1"));

        var jwt = JWSObject.parse(result.compactValue());
        assertThat(jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(key.toPublicJWK()))).isTrue();
        assertThat(jwt.getHeader().toJSONObject()).containsOnlyKeys("typ", "alg", "kid")
                .containsEntry("typ", "at+jwt")
                .containsEntry("alg", "ES256")
                .containsEntry("kid", "signing01");
        @SuppressWarnings("unchecked")
        var claims = new ObjectMapper().readValue(jwt.getPayload().toString(), java.util.Map.class);
        assertThat(claims).containsOnlyKeys("iss", "sub", "aud", "iat", "exp", "jti", "client_id",
                "token_profile", "token_version", "subject_kind", "scope", "app_id", "security_version", "cnf")
                .containsEntry("iss", ISSUER)
                .containsEntry("sub", subject.value())
                .containsEntry("aud", "https://api.dutch.example")
                .containsEntry("client_id", "dutch-mobile")
                .containsEntry("scope", "member:read")
                .containsEntry("app_id", "dutch-development")
                .containsEntry("security_version", 7);
        assertThat(claims.get("cnf")).isEqualTo(java.util.Map.of("jkt", THUMBPRINT));
        assertThat(jwt.getPayload().toString()).doesNotContain("hid_internal", "email", "phone", "credential");
        assertThat(result.toString()).doesNotContain(result.compactValue());
    }

    @Test
    void rotationSignsOnlyWithNewKeyWhileOverlapVerifiesBothAndRemovalRejectsOld() throws Exception {
        var oldKey = key("signing01");
        var newKey = key("signing02");
        var clock = Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC);
        var subject = new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        var oldToken = issuer(new TestSigner(oldKey, List.of(oldKey.toPublicJWK())), clock, subject)
                .issue(command(subject)).compactValue();
        var overlap = List.of(oldKey.toPublicJWK(), newKey.toPublicJWK());
        var newToken = issuer(new TestSigner(newKey, overlap), clock, subject).issue(command(subject)).compactValue();

        var cachedOld = new HumanAccessTokenVerifier(List.of(oldKey.toPublicJWK()), clock, ISSUER, Duration.ZERO);
        assertThat(cachedOld.verify(oldToken, registration(), 7).subject()).isEqualTo(subject);
        assertThatThrownBy(() -> cachedOld.verify(newToken, registration(), 7))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        var refreshed = new HumanAccessTokenVerifier(overlap, clock, ISSUER, Duration.ZERO);
        assertThat(refreshed.verify(oldToken, registration(), 7).subject()).isEqualTo(subject);
        assertThat(refreshed.verify(newToken, registration(), 7).subject()).isEqualTo(subject);
        var afterRemoval = new HumanAccessTokenVerifier(List.of(newKey.toPublicJWK()), clock, ISSUER, Duration.ZERO);
        assertThatThrownBy(() -> afterRemoval.verify(oldToken, registration(), 7))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        assertThat(JWSObject.parse(newToken).getHeader().getKeyID()).isEqualTo("signing02");
    }

    @Test void issuanceUsesOneCoherentSnapshotWithoutProviderReread() throws Exception {
        var key = key("signing01");
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        AccessTokenSigningCapability changing = () -> {
            if (reads.incrementAndGet() != 1) throw new IllegalStateException("second-read-canary");
            return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(),
                    List.of(key.toPublicJWK()), true, input -> {
                        try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
                        catch (Exception exception) { throw new IllegalStateException(exception); }
                    });
        };
        var subject = new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        var issuer = new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true, changing,
                () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), ISSUER, () -> ISSUER,
                Duration.ofMinutes(5));
        var token = issuer.issue(command(subject));
        assertThat(reads).hasValue(1);
        assertThat(JWSObject.parse(token.compactValue()).getHeader().getKeyID()).isEqualTo("signing01");
    }

    @Test
    void rejectsEveryNoncanonicalAuthorizationBindingAndUnsafeTimeOrMaterial() throws Exception {
        var key = key("signing01");
        var signer = new TestSigner(key, List.of(key.toPublicJWK()));
        var subject = new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        var invalid = List.of(
                changedAuthorization("other-app", "dutch-mobile", "dutch-api", "https://api.dutch.example", "member:read"),
                changedAuthorization("dutch-development", "other-client", "dutch-api", "https://api.dutch.example", "member:read"),
                changedAuthorization("dutch-development", "dutch-mobile", "other-resource", "https://api.dutch.example", "member:read"),
                changedAuthorization("dutch-development", "dutch-mobile", "dutch-api", "https://wrong.example", "member:read"),
                changedAuthorization("dutch-development", "dutch-mobile", "dutch-api", "https://api.dutch.example", "member:write"),
                changedAuthorization("dutch-development", "dutch-mobile", "dutch-api", "https://api.dutch.example", "Member:read"),
                changedAuthorization("dutch-development", "dutch-mobile", "dutch-api", "https://api.dutch.example", "member:read member:read"));
        for (var authorization : invalid) {
            var candidate = new HumanAccessTokenIssuer(registry(registration()), (identity, app, value) -> true,
                    signer, () -> "BBBBBBBBBBBBBBBBBBBBBB",
                    Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC),
                    ISSUER, () -> ISSUER, Duration.ofMinutes(5));
            assertThatThrownBy(() -> candidate.issue(new HumanAccessTokenIssueCommand(authorization, subject, 7,
                    new DpopKeyThumbprint(THUMBPRINT), "correlation-1")))
                    .isInstanceOf(HumanAccessTokenIssueException.class)
                    .hasMessage("access token could not be issued");
        }
        var unbound = new HumanAccessTokenIssuer(registry(registration()), (identity, app, value) -> false,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(),
                ISSUER, () -> ISSUER, Duration.ofMinutes(5));
        assertThatThrownBy(() -> unbound.issue(command(subject))).isInstanceOf(HumanAccessTokenIssueException.class);
        var weakJti = new HumanAccessTokenIssuer(registry(registration()), (identity, app, value) -> true,
                signer, () -> "too-short", Clock.systemUTC(), ISSUER, () -> ISSUER, Duration.ofMinutes(5));
        assertThatThrownBy(() -> weakJti.issue(command(subject))).isInstanceOf(HumanAccessTokenIssueException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(),
                ISSUER, () -> ISSUER, Duration.ofSeconds(59)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(),
                ISSUER, () -> ISSUER, Duration.ofSeconds(901)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), "http://unsafe.example", () -> ISSUER,
                Duration.ofMinutes(5))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), "https://attacker.example",
                () -> ISSUER, Duration.ofMinutes(5))).isInstanceOf(HumanAccessTokenIssueException.class)
                .hasMessage("access token could not be issued");
        assertThatThrownBy(() -> new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), null, () -> ISSUER,
                Duration.ofMinutes(5))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                signer, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), ISSUER, () -> ISSUER,
                Duration.ofSeconds(60).plusNanos(1)))
                .isInstanceOf(IllegalArgumentException.class);

        var absent = new HumanAccessTokenIssuer(registryWithNoRegistration(), (a, b, c) -> true, signer,
                () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), ISSUER, () -> ISSUER,
                Duration.ofMinutes(5));
        assertThatThrownBy(() -> absent.issue(command(subject))).isInstanceOf(HumanAccessTokenIssueException.class);
        var source = registration();
        var noDpop = new RegistrationManifest(source.manifestVersion(), source.appRegistrationId(), source.displayName(),
                source.environment(), source.client(), source.resource(),
                new RegistrationManifest.SecurityPolicy(1, false, "S256", List.of("authorization_code"), List.of()));
        var bearer = new HumanAccessTokenIssuer(registry(noDpop), (a, b, c) -> true, signer,
                () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), ISSUER, () -> ISSUER,
                Duration.ofMinutes(5));
        assertThatThrownBy(() -> bearer.issue(command(subject))).isInstanceOf(HumanAccessTokenIssueException.class);
    }

    @Test void containsDependencyFailuresWithoutLeakingProviderOrIdentityCanaries() throws Exception {
        var key = key("signing01");
        var signer = new TestSigner(key, List.of(key.toPublicJWK()));
        var subject = new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        var candidate = new HumanAccessTokenIssuer(registry(registration()),
                (identity, app, value) -> { throw new IllegalStateException("identity-provider-canary"); }, signer,
                () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(),
                ISSUER, () -> ISSUER, Duration.ofMinutes(5));
        assertThatThrownBy(() -> candidate.issue(command(subject)))
                .isInstanceOf(HumanAccessTokenIssueException.class)
                .hasMessage("access token could not be issued")
                .hasMessageNotContaining("provider-canary")
                .hasMessageNotContaining("hid_internal");
        var materialFailure = new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true, signer,
                () -> { throw new IllegalStateException("material-provider-canary"); }, Clock.systemUTC(),
                ISSUER, () -> ISSUER, Duration.ofMinutes(5));
        assertThatThrownBy(() -> materialFailure.issue(command(subject)))
                .isInstanceOf(HumanAccessTokenIssueException.class)
                .hasMessage("access token could not be issued")
                .hasMessageNotContaining("provider-canary")
                .hasMessageNotContaining("hid_internal");
        var mutableSigner = new MutableFailureSigner(key);
        var signingFailure = new HumanAccessTokenIssuer(registry(registration()), (a, b, c) -> true,
                mutableSigner, () -> "BBBBBBBBBBBBBBBBBBBBBB", Clock.systemUTC(), ISSUER, () -> ISSUER,
                Duration.ofMinutes(5));
        mutableSigner.fail = true;
        assertThatThrownBy(() -> signingFailure.issue(command(subject)))
                .isInstanceOf(HumanAccessTokenIssueException.class)
                .hasMessage("access token could not be issued")
                .hasMessageNotContaining("provider-secret-canary");
    }

    private static HumanAccessTokenIssuer issuer(TestSigner signer, Clock clock, AppSubject subject) {
        return new HumanAccessTokenIssuer(registry(registration()),
                (identity, app, candidate) -> identity.equals("hid_internal")
                        && app.equals("dutch-development") && candidate.equals(subject), signer,
                () -> "BBBBBBBBBBBBBBBBBBBBBB", clock, ISSUER, () -> ISSUER, Duration.ofMinutes(5));
    }

    private static HumanAccessTokenIssueCommand command(AppSubject subject) {
        return new HumanAccessTokenIssueCommand(authorization(), subject, 7,
                new DpopKeyThumbprint(THUMBPRINT), "correlation-1");
    }

    private static ConsumedAuthorization authorization() {
        return new ConsumedAuthorization("request", "dutch-development", "dutch-mobile", "dutch-api",
                "https://api.dutch.example", "hid_internal", "member:read", new byte[32], new byte[32]);
    }

    private static ECKey key(String keyId) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(keyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
    }

    private static ConsumedAuthorization changedAuthorization(String app, String client, String resource,
            String audience, String scope) {
        return new ConsumedAuthorization("request", app, client, resource, audience,
                "hid_internal", scope, new byte[32], new byte[32]);
    }

    private static RegistrationManifest registration() {
        return new RegistrationManifest(1, "dutch-development", "Dutch", "development",
                new RegistrationManifest.Client("dutch-mobile", "public_native",
                        List.of("dutch://oauth/callback"), List.of("authorization_code"), List.of("S256"), "external"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.example", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"), List.of()));
    }

    private static RegistrationRegistry registry(RegistrationManifest manifest) {
        return new RegistrationRegistry() {
            @Override public ReconciliationResult reconcile(ValidatedRegistration ignored) { throw new UnsupportedOperationException(); }
            @Override public Optional<RegistrationManifest> findByAppId(String id) { return id.equals(manifest.appRegistrationId()) ? Optional.of(manifest) : Optional.empty(); }
            @Override public Optional<RegistrationManifest> findByClientId(String id) { return Optional.empty(); }
            @Override public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
            @Override public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
            @Override public Optional<RegistrationManifest> findSoleRegistration() { return Optional.of(manifest); }
        };
    }

    private static RegistrationRegistry registryWithNoRegistration() {
        return new RegistrationRegistry() {
                    @Override public ReconciliationResult reconcile(ValidatedRegistration ignored) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public Optional<RegistrationManifest> findByAppId(String id) { return Optional.empty(); }
                    @Override public Optional<RegistrationManifest> findByClientId(String id) { return Optional.empty(); }
                    @Override public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
                    @Override public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
                    @Override public Optional<RegistrationManifest> findSoleRegistration() { return Optional.empty(); }
                };
    }

    private record TestSigner(ECKey key, List<ECKey> publicKeys) implements AccessTokenSigningCapability {
        @Override public AccessTokenSigningSnapshot snapshot() {
            return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(), publicKeys,
                    true, this::sign);
        }
        private byte[] sign(byte[] input) {
            try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
            catch (com.nimbusds.jose.JOSEException exception) { throw new IllegalStateException(exception); }
        }
    }

    private static final class MutableFailureSigner implements AccessTokenSigningCapability {
        private final TestSigner delegate;
        private boolean fail;
        private MutableFailureSigner(ECKey key) { delegate = new TestSigner(key, List.of(key.toPublicJWK())); }
        @Override public AccessTokenSigningSnapshot snapshot() {
            if (fail) throw new IllegalStateException("provider-secret-canary");
            var stable = delegate.snapshot();
            return new AccessTokenSigningSnapshot(stable.purpose(), stable.algorithm(), stable.activeKeyId(),
                    stable.publicJwks(), stable.selfCheck(), this::sign);
        }
        private byte[] sign(byte[] input) {
            if (fail) throw new IllegalStateException("provider-secret-canary");
            return delegate.snapshot().sign(input);
        }
    }
}
