package dev.distracted.iam.platform.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Secret-backed key material for a local development runtime.
 *
 * <p>Every value is injected from the environment. Nothing here has a default, and the
 * configuration only activates for the {@code development} profile.
 */
@ConfigurationProperties("iam.crypto.local")
public record LocalCryptographicCapabilityProperties(
        String provider,
        String signerKeyId,
        String signerPrivateKey,
        String identifierEncryptionKeyReference,
        String identifierEncryptionKey,
        Short identifierEncryptionKeyVersion,
        String blindIndexKeyReference,
        String blindIndexKey,
        Short blindIndexKeyVersion,
        String challengeDigestKeyReference,
        String challengeDigestKey,
        Short challengeDigestKeyVersion) {
}
