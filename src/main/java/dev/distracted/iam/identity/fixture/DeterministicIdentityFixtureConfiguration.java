package dev.distracted.iam.identity.fixture;

import dev.distracted.iam.identity.IdentityEvidenceService;
import dev.distracted.iam.identity.IdentityService;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StartupCheckedCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.TokenSignerCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile("development | test")
@ConditionalOnProperty(name = "iam.fixtures.deterministic-identity.enabled", havingValue = "true")
public class DeterministicIdentityFixtureConfiguration {
    @Bean(destroyMethod = "close")
    FixtureChallengeDelivery fixtureChallengeDelivery() { return new FixtureChallengeDelivery(); }

    @Bean
    FixtureCapabilityGate fixtureCapabilityGate(List<StructuredIdentifierEncryptionCapability> encryptors,
            List<VersionedBlindIndexCapability> indexes, List<ChallengeDigestCapability> digests,
            List<TokenSignerCapability> signers) {
        return new FixtureCapabilityGate(encryptors, indexes, digests, signers);
    }

    @Bean
    DeterministicIdentityFixtureRunner deterministicIdentityFixtureRunner(IdentityService identities,
            IdentityEvidenceService evidence, OneShotChallengeReceipt receipts, FixtureCapabilityGate ignoredGate) {
        return new DeterministicIdentityFixtureRunner(identities, evidence, receipts);
    }
}

final class FixtureCapabilityGate {
    FixtureCapabilityGate(List<StructuredIdentifierEncryptionCapability> encryptors,
            List<VersionedBlindIndexCapability> indexes, List<ChallengeDigestCapability> digests,
            List<TokenSignerCapability> signers) {
        requireOneHealthy(encryptors, CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", "fixture_encryption");
        requireOneHealthy(indexes, CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", "fixture_blind_index");
        requireOneHealthy(digests, CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", "fixture_digest");
        var signerMetadata = requireOneHealthy(
                signers, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", "fixture_signer");
        var references = new java.util.ArrayList<String>();
        try {
            addVersionedReferences(encryptors.getFirst().keyReferences(), references);
            addVersionedReferences(indexes.getFirst().keyReferences(), references);
            addVersionedReferences(digests.getFirst().keyReferences(), references);
            addReference(signerMetadata.keyReference(), references);
        } catch (FixtureException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new FixtureException("fixture_key_references_invalid");
        }
        if (new java.util.HashSet<>(references).size() != references.size()) {
            throw new FixtureException("fixture_key_purpose_reuse");
        }
    }

    private static void addVersionedReferences(java.util.Map<Short, String> values, java.util.List<String> target) {
        if (values == null || values.isEmpty()) throw new FixtureException("fixture_key_references_invalid");
        values.values().forEach(value -> addReference(value, target));
    }

    private static void addReference(String value, java.util.List<String> target) {
        if (value == null || value.isBlank()) throw new FixtureException("fixture_key_references_invalid");
        target.add(value);
    }

    private static dev.distracted.iam.platform.crypto.CapabilityMetadata requireOneHealthy(
            List<? extends StartupCheckedCapability> values, CapabilityPurpose purpose,
            String algorithm, String code) {
        if (values.size() != 1) throw new FixtureException(code + "_unavailable");
        try {
            var capability = values.getFirst();
            var metadata = capability.metadata();
            var health = capability.selfCheck();
            if (metadata == null || health == null || !health.healthy() || metadata.purpose() != purpose
                    || !algorithm.equals(metadata.algorithm())) throw new FixtureException(code + "_unhealthy");
            return metadata;
        } catch (FixtureException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new FixtureException(code + "_unhealthy");
        }
    }
}
