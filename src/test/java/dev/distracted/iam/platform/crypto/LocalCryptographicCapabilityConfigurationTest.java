package dev.distracted.iam.platform.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class LocalCryptographicCapabilityConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(LocalCryptographicCapabilityConfiguration.class)
            .withPropertyValues("spring.profiles.active=development")
            .withPropertyValues(validMaterial());

    @Test
    void wiresEveryCapabilityFromSecretBackedMaterial() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(TokenSignerCapability.class);
            assertThat(context).hasSingleBean(StructuredIdentifierEncryptionCapability.class);
            assertThat(context).hasSingleBean(VersionedBlindIndexCapability.class);
            assertThat(context).hasSingleBean(ChallengeDigestCapability.class);

            assertThat(context.getBean(TokenSignerCapability.class).selfCheck().healthy()).isTrue();
            assertThat(context.getBean(ChallengeDigestCapability.class).digest(
                    "development", "challenge", "code")).hasSize(32);
            assertThat(context.getBean(StructuredIdentifierEncryptionCapability.class).keyVersion()).isEqualTo((short) 1);
        });
    }

    @Test
    void defaultsEveryKeyVersionToOne() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(VersionedBlindIndexCapability.class).keyVersion()).isEqualTo((short) 1);
            assertThat(context.getBean(ChallengeDigestCapability.class).keyVersion()).isEqualTo((short) 1);
        });
    }

    @Test
    void usesAnExplicitPositiveKeyVersion() {
        contextRunner.withPropertyValues("iam.crypto.local.blind-index-key-version=2")
                .run(context -> assertThat(context.getBean(VersionedBlindIndexCapability.class).keyVersion())
                        .isEqualTo((short) 2));
    }

    @Test
    void failsClosedWhenSecretMaterialIsUnset() {
        var material = Arrays.stream(validMaterial())
                .filter(property -> !property.startsWith("iam.crypto.local.signer-private-key="))
                .toArray(String[]::new);
        new ApplicationContextRunner()
                .withUserConfiguration(LocalCryptographicCapabilityConfiguration.class)
                .withPropertyValues("spring.profiles.active=development")
                .withPropertyValues(material)
                .run(context -> assertStartupFailure(context.getStartupFailure(),
                        "local_crypto_configuration_missing:signer-private-key"));
    }

    @Test
    void failsClosedWhenSecretMaterialIsMissing() {
        contextRunner.withPropertyValues("iam.crypto.local.signer-private-key=")
                .run(context -> assertStartupFailure(context.getStartupFailure(),
                        "local_crypto_configuration_missing:signer-private-key"));
    }

    @Test
    void failsClosedWhenAReferenceIsBlank() {
        contextRunner.withPropertyValues("iam.crypto.local.signer-key-id=")
                .run(context -> assertStartupFailure(context.getStartupFailure(),
                        "local_crypto_configuration_missing:signer-key-id"));
    }

    @Test
    void failsClosedWhenMaterialIsNotBase64() {
        contextRunner.withPropertyValues("iam.crypto.local.blind-index-key=not base64!")
                .run(context -> assertStartupFailure(context.getStartupFailure(),
                        "local_crypto_material_invalid:blind-index-key"));
    }

    @Test
    void failsClosedWhenAKeyVersionIsNotPositive() {
        contextRunner.withPropertyValues("iam.crypto.local.challenge-digest-key-version=0")
                .run(context -> assertStartupFailure(context.getStartupFailure(),
                        "local_crypto_key_version_invalid"));
    }

    @Test
    void doesNotActivateOutsideTheDevelopmentProfile() {
        new ApplicationContextRunner()
                .withUserConfiguration(LocalCryptographicCapabilityConfiguration.class)
                .withPropertyValues(validMaterial())
                .withPropertyValues(
                        "spring.profiles.active=test",
                        "iam.crypto.local.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(TokenSignerCapability.class);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"staging", "production", "production-like"})
    void doesNotActivateWhenDevelopmentIsCombinedWithAProductionLikeProfile(String profile) {
        contextRunner.withPropertyValues("spring.profiles.active=development," + profile)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(TokenSignerCapability.class);
                });
    }

    private static void assertStartupFailure(Throwable failure, String message) {
        assertThat(failure).isNotNull();
        assertThat(failure).hasStackTraceContaining(message);
    }

    private static String[] validMaterial() {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            var signerMaterial = encode(generator.generateKeyPair().getPrivate().getEncoded());
            List<String> values = new ArrayList<>(List.of(
                    "iam.crypto.local.enabled=true",
                    "iam.crypto.local.provider=local-jca",
                    "iam.crypto.local.signer-key-id=local-signing-v1",
                    "iam.crypto.local.signer-private-key=" + signerMaterial,
                    "iam.crypto.local.identifier-encryption-key-reference=local-encryption-v1",
                    "iam.crypto.local.identifier-encryption-key=" + encode(new byte[32]),
                    "iam.crypto.local.blind-index-key-reference=local-blind-index-v1",
                    "iam.crypto.local.blind-index-key=" + encode(new byte[32]),
                    "iam.crypto.local.challenge-digest-key-reference=local-challenge-digest-v1",
                    "iam.crypto.local.challenge-digest-key=" + encode(new byte[32])));
            return values.toArray(String[]::new);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String encode(byte[] material) {
        return Base64.getEncoder().encodeToString(material);
    }
}
