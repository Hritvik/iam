package dev.distracted.iam.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.platform.crypto.BlindIndexCapability;
import dev.distracted.iam.platform.crypto.CapabilityMetadata;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.CapabilitySelfCheck;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.IdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.SealedIdentifierValue;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import dev.distracted.iam.platform.crypto.TokenSignerCapability;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtEncoder;

class ProductionCapabilityConfigurationTest {
    private static final String[] EXPLICIT_REFERENCES = {
        "iam.crypto.signer-provider=external-kms",
        "iam.crypto.signer-key-id=key-reference",
        "iam.crypto.signer-algorithm=ES256",
        "iam.crypto.identifier-encryption-key-reference=encryption-key-reference",
        "iam.crypto.blind-index-key-reference=blind-index-key-reference",
        "iam.crypto.challenge-digest-key-reference=challenge-digest-key-reference"
    };

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withUserConfiguration(IamApplication.class)
            .withPropertyValues(
                    "spring.profiles.active=production-like",
                    "spring.autoconfigure.exclude="
                            + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                            + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration");

    @Test
    void productionStartupFailsWithoutExternalCryptographicCapabilities() {
        contextRunner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootCause(context.getStartupFailure()))
                    .hasMessageContaining("Missing required production cryptographic capabilities");
        });
    }

    @Test
    void externalReferencesWithoutUsableCapabilitiesRemainFailClosed() {
        contextRunner.withPropertyValues(EXPLICIT_REFERENCES).run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootCause(context.getStartupFailure()))
                    .hasMessageContaining("Missing required production cryptographic capability beans");
        });
    }

    @Test
    void healthyExplicitCapabilitiesStartARealWebContextWithoutSynthesizedAuthentication() {
        withCapabilities(
                        signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(UserDetailsService.class);
                    assertThat(context).doesNotHaveBean(JwtEncoder.class);
                    assertThat(context).hasSingleBean(TokenSignerCapability.class);
                    assertThat(context).hasSingleBean(IdentifierEncryptionCapability.class);
                    assertThat(context).hasSingleBean(BlindIndexCapability.class);
                    assertThat(context).hasSingleBean(ChallengeDigestCapability.class);
                    assertThat(context).doesNotHaveBean("defaultSecurityFilterChain");
                    assertThat(context).hasBean("foundationSecurityFilterChain");
                    assertThat(context).doesNotHaveBean("deterministicIdentityFixtureRunner");
                    assertThat(context).doesNotHaveBean("fixtureChallengeDelivery");
                });
    }

    @Test
    void healthyProductionLikeStillRejectsFixtureOptInForTheFixtureReason() {
        withCapabilities(
                        signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .withPropertyValues("iam.fixtures.deterministic-identity.enabled=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootCause(context.getStartupFailure())).hasMessage("fixture_profile_forbidden");
                });
    }

    @Test
    void rejectsWrongPurposeOrAlgorithm() {
        withCapabilities(
                        signer(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "ES256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .run(context -> assertStartupFailure(context.getStartupFailure(), "signer_purpose_mismatch"));

        withCapabilities(
                        signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "RS256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .run(context -> assertStartupFailure(context.getStartupFailure(), "signer_algorithm_not_allowed"));

        withCapabilities(
                        signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-128-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .run(context -> assertStartupFailure(context.getStartupFailure(), "encryption_algorithm_not_allowed"));

        withCapabilities(
                        signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-512", CapabilitySelfCheck.ready()))
                .run(context -> assertStartupFailure(context.getStartupFailure(), "blind_index_algorithm_not_allowed"));
    }

    @Test
    void rejectsFailedStartupSelfCheck() {
        withCapabilities(
                        signer(
                                CapabilityPurpose.ACCESS_TOKEN_SIGNING,
                                "ES256",
                                CapabilitySelfCheck.unhealthy("signer_unavailable")),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .run(context -> assertStartupFailure(context.getStartupFailure(), "signer_self_check_failed"));
    }

    @Test
    void rejectsMetadataThatDoesNotMatchExternalReferences() {
        withCapabilities(
                        signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", CapabilitySelfCheck.ready()),
                        encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                        blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()))
                .withPropertyValues("iam.crypto.signer-key-id=different-key-reference")
                .run(context -> assertStartupFailure(context.getStartupFailure(), "signer_reference_mismatch"));
    }

    @Test
    void rejectsKeyReferenceReuseAcrossCryptographicPurposes() {
        withCapabilities(
                signer(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", CapabilitySelfCheck.ready()),
                encryption(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", CapabilitySelfCheck.ready()),
                blindIndex(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", CapabilitySelfCheck.ready()),
                challengeDigest("encryption-key-reference"))
                .withPropertyValues("iam.crypto.challenge-digest-key-reference=encryption-key-reference")
                .run(context -> assertStartupFailure(context.getStartupFailure(), "crypto_key_purpose_reuse"));
    }

    private WebApplicationContextRunner withCapabilities(
            TokenSignerCapability signer,
            StructuredIdentifierEncryptionCapability encryption,
            VersionedBlindIndexCapability blindIndex) {
        return withCapabilities(signer, encryption, blindIndex, challengeDigest());
    }

    private WebApplicationContextRunner withCapabilities(TokenSignerCapability signer,
            StructuredIdentifierEncryptionCapability encryption, VersionedBlindIndexCapability blindIndex,
            ChallengeDigestCapability challengeDigest) {
        return contextRunner.withPropertyValues(EXPLICIT_REFERENCES)
                .withBean(TokenSignerCapability.class, () -> signer)
                .withBean(IdentifierEncryptionCapability.class, () -> encryption)
                .withBean(VersionedBlindIndexCapability.class, () -> blindIndex)
                .withBean(ChallengeDigestCapability.class, () -> challengeDigest);
    }

    private static void assertStartupFailure(Throwable failure, String code) {
        assertThat(failure).isNotNull();
        assertThat(rootCause(failure))
                .hasMessageContaining("Production cryptographic capability validation failed")
                .hasMessageContaining(code);
    }

    private static Throwable rootCause(Throwable throwable) {
        var current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static TokenSignerCapability signer(
            CapabilityPurpose purpose,
            String algorithm,
            CapabilitySelfCheck selfCheck) {
        var metadata = new CapabilityMetadata(purpose, "external-kms", "key-reference", algorithm);
        return new TokenSignerCapability() {
            @Override
            public CapabilityMetadata metadata() {
                return metadata;
            }

            @Override
            public CapabilitySelfCheck selfCheck() {
                return selfCheck;
            }

            @Override
            public byte[] sign(byte[] signingInput) {
                return "test-signature".getBytes(StandardCharsets.US_ASCII);
            }
        };
    }

    private static StructuredIdentifierEncryptionCapability encryption(
            CapabilityPurpose purpose,
            String algorithm,
            CapabilitySelfCheck selfCheck) {
        var metadata = new CapabilityMetadata(purpose, "external-kms", "encryption-key-reference", algorithm);
        return new StructuredIdentifierEncryptionCapability() {
            @Override
            public CapabilityMetadata metadata() {
                return metadata;
            }

            @Override
            public CapabilitySelfCheck selfCheck() {
                return selfCheck;
            }

            @Override
            public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
                return plaintext.clone();
            }

            @Override
            public byte[] decrypt(byte[] ciphertext, byte[] associatedData) {
                return ciphertext.clone();
            }

            @Override
            public SealedIdentifierValue seal(byte[] plaintext, byte[] associatedData) {
                return new SealedIdentifierValue(plaintext, new byte[12], new byte[16], (short) 1);
            }

            @Override
            public byte[] open(SealedIdentifierValue sealed, byte[] associatedData) {
                return sealed.ciphertext();
            }

            @Override public short keyVersion() { return 1; }
            @Override public java.util.Set<Short> readableKeyVersions() { return java.util.Set.of((short) 1); }
            @Override public java.util.Map<Short, String> keyReferences() {
                return java.util.Map.of((short) 1, "encryption-key-reference");
            }
        };
    }

    private static VersionedBlindIndexCapability blindIndex(
            CapabilityPurpose purpose,
            String algorithm,
            CapabilitySelfCheck selfCheck) {
        var metadata = new CapabilityMetadata(purpose, "external-kms", "blind-index-key-reference", algorithm);
        return new VersionedBlindIndexCapability() {
            @Override
            public CapabilityMetadata metadata() {
                return metadata;
            }

            @Override
            public CapabilitySelfCheck selfCheck() {
                return selfCheck;
            }

            @Override
            public byte[] derive(byte[] canonicalValue) {
                return canonicalValue.clone();
            }
            @Override public byte[] derive(String environment, dev.distracted.iam.identity.IdentifierType type,
                    short normalizationVersion, String canonicalValue) { return canonicalValue.getBytes(); }
            @Override public byte[] deriveForVersion(short keyVersion, String environment,
                    dev.distracted.iam.identity.IdentifierType type, short normalizationVersion,
                    String canonicalValue) { return canonicalValue.getBytes(); }
            @Override public java.util.Map<Short, byte[]> deriveReadable(String environment,
                    dev.distracted.iam.identity.IdentifierType type, short normalizationVersion,
                    String canonicalValue) { return java.util.Map.of((short) 1, canonicalValue.getBytes()); }
            @Override public short keyVersion() { return 1; }
            @Override public java.util.Set<Short> requiredWriteKeyVersions() { return java.util.Set.of((short) 1); }
            @Override public java.util.Set<Short> readableKeyVersions() { return java.util.Set.of((short) 1); }
            @Override public java.util.Map<Short, String> keyReferences() {
                return java.util.Map.of((short) 1, "blind-index-key-reference");
            }
        };
    }

    private static ChallengeDigestCapability challengeDigest() {
        return challengeDigest("challenge-digest-key-reference");
    }

    private static ChallengeDigestCapability challengeDigest(String reference) {
        var metadata = new CapabilityMetadata(CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST,
                "external-kms", reference, "HMAC-SHA-256");
        return new ChallengeDigestCapability() {
            @Override public byte[] digest(String environment, String challengeId, String code) {
                return new byte[32];
            }
            @Override public byte[] digest(short keyVersion, String environment, String challengeId, String code) {
                return new byte[32];
            }
            @Override public short keyVersion() { return 1; }
            @Override public java.util.Set<Short> readableKeyVersions() { return java.util.Set.of((short) 1); }
            @Override public java.util.Map<Short, String> keyReferences() {
                return java.util.Map.of((short) 1, reference);
            }
            @Override public CapabilityMetadata metadata() { return metadata; }
            @Override public CapabilitySelfCheck selfCheck() { return CapabilitySelfCheck.ready(); }
        };
    }
}

