package dev.distracted.iam.authorization;

import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile("production | staging | production-like")
@ConditionalOnProperty(name = "iam.authorization.enabled", havingValue = "true")
@EnableConfigurationProperties(AuthorizationCodeCapabilityProperties.class)
public class AuthorizationProductionCapabilityConfiguration {
    public AuthorizationProductionCapabilityConfiguration(AuthorizationCodeCapabilityProperties properties,
            List<AuthorizationCodeDigestCapability> capabilities,
            List<StructuredIdentifierEncryptionCapability> encryption,
            List<VersionedBlindIndexCapability> blindIndexes,
            List<ChallengeDigestCapability> challengeDigests) {
        if (capabilities.size() != 1) throw new IllegalStateException("authorization_code_digest_capability_required");
        var capability = capabilities.getFirst();
        var metadata = capability.metadata();
        var reference = properties.codeDigestKeyReference();
        if (metadata.purpose() != CapabilityPurpose.AUTHORIZATION_CODE_DIGEST
                || !"HMAC-SHA-256".equals(metadata.algorithm())
                || reference == null || reference.isBlank() || !reference.equals(metadata.keyReference())
                || !capability.selfCheck().healthy()
                || !capability.readableKeyVersions().contains(capability.keyVersion())
                || reused(capability, encryption, blindIndexes, challengeDigests)) {
            throw new IllegalStateException("authorization_code_digest_capability_invalid");
        }
    }

    private static boolean reused(AuthorizationCodeDigestCapability capability,
            List<StructuredIdentifierEncryptionCapability> encryption,
            List<VersionedBlindIndexCapability> blindIndexes, List<ChallengeDigestCapability> challengeDigests) {
        var references = new java.util.HashSet<>(capability.keyReferences().values());
        return encryption.stream().flatMap(value -> value.keyReferences().values().stream()).anyMatch(references::contains)
                || blindIndexes.stream().flatMap(value -> value.keyReferences().values().stream()).anyMatch(references::contains)
                || challengeDigests.stream().flatMap(value -> value.keyReferences().values().stream()).anyMatch(references::contains);
    }
}
