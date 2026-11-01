package dev.distracted.iam.platform.crypto;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile("production | staging | production-like")
@EnableConfigurationProperties(CryptographicCapabilityProperties.class)
public class ProductionCryptographicCapabilityConfiguration {
    private static final String SIGNING_ALGORITHM = "ES256";
    private static final String ENCRYPTION_ALGORITHM = "AES-256-GCM";
    private static final String BLIND_INDEX_ALGORITHM = "HMAC-SHA-256";

    public ProductionCryptographicCapabilityConfiguration(
            CryptographicCapabilityProperties properties,
            List<TokenSignerCapability> signers,
            List<StructuredIdentifierEncryptionCapability> encryptors,
            List<VersionedBlindIndexCapability> blindIndexes,
            List<ChallengeDigestCapability> challengeDigests) {
        var missingReferences = missingReferences(properties);
        if (!missingReferences.isEmpty()) {
            throw new IllegalStateException(
                    "Missing required production cryptographic capabilities: "
                            + String.join(", ", missingReferences));
        }

        var beanFailures = beanCardinalityFailures(signers, encryptors, blindIndexes, challengeDigests);
        if (!beanFailures.isEmpty()) {
            throw new IllegalStateException(
                    "Missing required production cryptographic capability beans: "
                            + String.join(", ", beanFailures));
        }

        var failures = new ArrayList<String>();
        validateSigner(properties, signers.getFirst(), failures);
        validateEncryption(properties, encryptors.getFirst(), failures);
        validateBlindIndex(properties, blindIndexes.getFirst(), failures);
        validateChallengeDigest(properties, challengeDigests.getFirst(), failures);
        validatePurposeSeparation(encryptors.getFirst(), blindIndexes.getFirst(), challengeDigests.getFirst(), failures);
        if (!failures.isEmpty()) {
            throw new IllegalStateException(
                    "Production cryptographic capability validation failed: "
                            + String.join(", ", failures));
        }
    }

    private static List<String> missingReferences(CryptographicCapabilityProperties properties) {
        var missing = new ArrayList<String>();
        requireText(properties.signerProvider(), "signer.provider", missing);
        requireText(properties.signerKeyId(), "signer.key-id", missing);
        requireText(properties.signerAlgorithm(), "signer.algorithm", missing);
        requireText(properties.identifierEncryptionKeyReference(), "identifier-encryption.key-reference", missing);
        requireText(properties.blindIndexKeyReference(), "blind-index.key-reference", missing);
        requireText(properties.challengeDigestKeyReference(), "challenge-digest.key-reference", missing);
        return List.copyOf(missing);
    }

    private static List<String> beanCardinalityFailures(
            List<TokenSignerCapability> signers,
            List<StructuredIdentifierEncryptionCapability> encryptors,
            List<VersionedBlindIndexCapability> blindIndexes,
            List<ChallengeDigestCapability> challengeDigests) {
        var failures = new ArrayList<String>();
        requireExactlyOne(signers, "signer", failures);
        requireExactlyOne(encryptors, "identifier_encryption", failures);
        requireExactlyOne(blindIndexes, "blind_index", failures);
        requireExactlyOne(challengeDigests, "challenge_digest", failures);
        return List.copyOf(failures);
    }

    private static void validateChallengeDigest(CryptographicCapabilityProperties properties,
            ChallengeDigestCapability capability, List<String> failures) {
        var metadata = metadata(capability, "challenge_digest", failures);
        if (metadata == null) return;
        requirePurpose(metadata, CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "challenge_digest", failures);
        requireAlgorithm(metadata, BLIND_INDEX_ALGORITHM, "challenge_digest", failures);
        requireEqual(metadata.keyReference(), properties.challengeDigestKeyReference(),
                "challenge_digest_reference_mismatch", failures);
        requireHealthy(capability, "challenge_digest", failures);
        requireReadableWriteVersion(capability.keyVersion(), capability.readableKeyVersions(),
                "challenge_digest", failures);
    }

    private static void validateSigner(
            CryptographicCapabilityProperties properties,
            TokenSignerCapability capability,
            List<String> failures) {
        var metadata = metadata(capability, "signer", failures);
        if (metadata == null) {
            return;
        }
        requirePurpose(metadata, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "signer", failures);
        requireAlgorithm(metadata, SIGNING_ALGORITHM, "signer", failures);
        requireEqual(metadata.provider(), properties.signerProvider(), "signer_provider_mismatch", failures);
        requireEqual(metadata.keyReference(), properties.signerKeyId(), "signer_reference_mismatch", failures);
        requireEqual(metadata.algorithm(), properties.signerAlgorithm(), "signer_config_algorithm_mismatch", failures);
        requireHealthy(capability, "signer", failures);
    }

    private static void validateEncryption(
            CryptographicCapabilityProperties properties,
            StructuredIdentifierEncryptionCapability capability,
            List<String> failures) {
        var metadata = metadata(capability, "encryption", failures);
        if (metadata == null) {
            return;
        }
        requirePurpose(metadata, CapabilityPurpose.IDENTIFIER_ENCRYPTION, "encryption", failures);
        requireAlgorithm(metadata, ENCRYPTION_ALGORITHM, "encryption", failures);
        requireEqual(
                metadata.keyReference(),
                properties.identifierEncryptionKeyReference(),
                "encryption_reference_mismatch",
                failures);
        requireHealthy(capability, "encryption", failures);
        requireReadableWriteVersion(capability.keyVersion(), capability.readableKeyVersions(), "encryption", failures);
    }

    private static void validateBlindIndex(
            CryptographicCapabilityProperties properties,
            VersionedBlindIndexCapability capability,
            List<String> failures) {
        var metadata = metadata(capability, "blind_index", failures);
        if (metadata == null) {
            return;
        }
        requirePurpose(metadata, CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "blind_index", failures);
        requireAlgorithm(metadata, BLIND_INDEX_ALGORITHM, "blind_index", failures);
        requireEqual(
                metadata.keyReference(),
                properties.blindIndexKeyReference(),
                "blind_index_reference_mismatch",
                failures);
        requireHealthy(capability, "blind_index", failures);
        requireReadableWriteVersion(capability.keyVersion(), capability.readableKeyVersions(), "blind_index", failures);
        if (capability.requiredWriteKeyVersions() == null || capability.requiredWriteKeyVersions().isEmpty()
                || !capability.readableKeyVersions().containsAll(capability.requiredWriteKeyVersions())) {
            failures.add("blind_index_required_write_versions_unreadable");
        }
    }

    private static void validatePurposeSeparation(StructuredIdentifierEncryptionCapability encryption,
            VersionedBlindIndexCapability blindIndex, ChallengeDigestCapability challengeDigest,
            List<String> failures) {
        var references = new java.util.HashSet<String>();
        var expected = encryption.keyReferences().size() + blindIndex.keyReferences().size()
                + challengeDigest.keyReferences().size();
        references.addAll(encryption.keyReferences().values());
        references.addAll(blindIndex.keyReferences().values());
        references.addAll(challengeDigest.keyReferences().values());
        if (references.size() != expected) failures.add("crypto_key_purpose_reuse");
    }

    private static void requireReadableWriteVersion(short writeVersion, java.util.Set<Short> readable,
            String name, List<String> failures) {
        if (readable == null || !readable.contains(writeVersion)) failures.add(name + "_write_version_unreadable");
    }

    private static CapabilityMetadata metadata(
            StartupCheckedCapability capability,
            String name,
            List<String> failures) {
        try {
            var metadata = capability.metadata();
            if (metadata == null) {
                failures.add(name + "_metadata_missing");
            }
            return metadata;
        } catch (RuntimeException exception) {
            failures.add(name + "_metadata_failed");
            return null;
        }
    }

    private static void requireHealthy(
            StartupCheckedCapability capability,
            String name,
            List<String> failures) {
        try {
            var result = capability.selfCheck();
            if (result == null || !result.healthy()) {
                failures.add(name + "_self_check_failed");
            }
        } catch (RuntimeException exception) {
            failures.add(name + "_self_check_failed");
        }
    }

    private static void requirePurpose(
            CapabilityMetadata metadata,
            CapabilityPurpose required,
            String name,
            List<String> failures) {
        if (metadata.purpose() != required) {
            failures.add(name + "_purpose_mismatch");
        }
    }

    private static void requireAlgorithm(
            CapabilityMetadata metadata,
            String required,
            String name,
            List<String> failures) {
        if (!required.equals(metadata.algorithm())) {
            failures.add(name + "_algorithm_not_allowed");
        }
    }

    private static void requireEqual(
            String actual,
            String required,
            String failure,
            List<String> failures) {
        if (!required.equals(actual)) {
            failures.add(failure);
        }
    }

    private static void requireText(String value, String capability, List<String> missing) {
        if (value == null || value.isBlank()) {
            missing.add(capability);
        }
    }

    private static void requireExactlyOne(List<?> capabilities, String name, List<String> failures) {
        if (capabilities.size() != 1) {
            failures.add(name + "_bean_count_" + capabilities.size());
        }
    }
}

