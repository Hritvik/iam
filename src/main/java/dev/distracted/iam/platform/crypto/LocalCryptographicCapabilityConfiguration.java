package dev.distracted.iam.platform.crypto;

import java.util.Base64;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Wires the four cryptographic capabilities from secret-backed key material so the service can run
 * with the {@code development} profile outside tests.
 *
 * <p>Scoped to {@code development} on purpose: staging and production must supply their capabilities
 * through their own custody configuration, and {@link ProductionCryptographicCapabilityConfiguration}
 * keeps failing closed until they do.
 */
@Configuration(proxyBeanMethods = false)
@Profile("development & !staging & !production & !production-like")
@ConditionalOnProperty(name = "iam.crypto.local.enabled", havingValue = "true")
@EnableConfigurationProperties(LocalCryptographicCapabilityProperties.class)
public class LocalCryptographicCapabilityConfiguration {
    @Bean
    TokenSignerCapability localTokenSigner(LocalCryptographicCapabilityProperties properties) {
        return new JcaEs256TokenSignerCapability(
                required(properties.provider(), "provider"),
                required(properties.signerKeyId(), "signer-key-id"),
                "ES256",
                decode(properties.signerPrivateKey(), "signer-private-key"));
    }

    @Bean
    StructuredIdentifierEncryptionCapability localIdentifierEncryption(LocalCryptographicCapabilityProperties properties) {
        return new AesGcmIdentifierEncryptionCapability(
                required(properties.identifierEncryptionKeyReference(), "identifier-encryption-key-reference"),
                version(properties.identifierEncryptionKeyVersion()),
                decode(properties.identifierEncryptionKey(), "identifier-encryption-key"));
    }

    @Bean
    VersionedBlindIndexCapability localBlindIndex(LocalCryptographicCapabilityProperties properties) {
        return new HmacBlindIndexCapability(
                required(properties.blindIndexKeyReference(), "blind-index-key-reference"),
                version(properties.blindIndexKeyVersion()),
                decode(properties.blindIndexKey(), "blind-index-key"));
    }

    @Bean
    ChallengeDigestCapability localChallengeDigest(LocalCryptographicCapabilityProperties properties) {
        return new HmacChallengeDigestCapability(
                required(properties.challengeDigestKeyReference(), "challenge-digest-key-reference"),
                version(properties.challengeDigestKeyVersion()),
                decode(properties.challengeDigestKey(), "challenge-digest-key"));
    }

    private static short version(Short value) {
        if (value == null) {
            return 1;
        }
        if (value < 1) {
            throw new IllegalStateException("local_crypto_key_version_invalid");
        }
        return value;
    }

    private static byte[] decode(String value, String name) {
        try {
            return Base64.getDecoder().decode(required(value, name));
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("local_crypto_material_invalid:" + name, exception);
        }
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("local_crypto_configuration_missing:" + name);
        }
        return value;
    }
}
