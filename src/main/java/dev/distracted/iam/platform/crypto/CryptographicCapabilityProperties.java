package dev.distracted.iam.platform.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.crypto")
public record CryptographicCapabilityProperties(
        String signerProvider,
        String signerKeyId,
        String signerAlgorithm,
        String identifierEncryptionKeyReference,
        String blindIndexKeyReference,
        String challengeDigestKeyReference) {
}

