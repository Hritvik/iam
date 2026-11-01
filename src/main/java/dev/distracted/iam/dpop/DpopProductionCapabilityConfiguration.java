package dev.distracted.iam.dpop;

import dev.distracted.iam.authorization.AuthorizationCodeDigestCapability;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import dev.distracted.iam.token.AccessTokenSigningCapability;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile("production | staging | production-like")
@ConditionalOnProperty(name = "iam.dpop.enabled", havingValue = "true")
@EnableConfigurationProperties(DpopCapabilityProperties.class)
public class DpopProductionCapabilityConfiguration {
    public DpopProductionCapabilityConfiguration(DpopCapabilityProperties properties,
                                                  List<DpopStateDigestCapability> capabilities,
                                                  List<AuthorizationCodeDigestCapability> codeDigests,
                                                  List<StructuredIdentifierEncryptionCapability> encryption,
                                                  List<VersionedBlindIndexCapability> blindIndexes,
                                                  List<ChallengeDigestCapability> challengeDigests,
                                                  List<AccessTokenSigningCapability> signingCapabilities) {
        if (capabilities.size() != 1) throw new IllegalStateException("dpop_state_digest_capability_required");
        var capability = capabilities.getFirst();
        try {
            var metadata = capability.metadata();
            var configuredReference = properties.stateDigestKeyReference();
            if (!properties.enabled() || metadata.purpose() != CapabilityPurpose.DPOP_STATE_DIGEST
                    || !"HMAC-SHA-256".equals(metadata.algorithm())
                    || configuredReference == null || configuredReference.isBlank()
                    || !configuredReference.equals(metadata.keyReference())
                    || !capability.selfCheck().healthy()
                    || !capability.readableKeyVersions().contains(capability.keyVersion())
                    || !configuredReference.equals(capability.keyReferences().get(capability.keyVersion()))
                    || reused(configuredReference, codeDigests, encryption, blindIndexes,
                            challengeDigests, signingCapabilities)) {
                throw new IllegalStateException("dpop_state_digest_capability_invalid");
            }
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new IllegalStateException("dpop_state_digest_capability_invalid");
        }
    }

    private static boolean reused(String reference, List<AuthorizationCodeDigestCapability> codeDigests,
                                  List<StructuredIdentifierEncryptionCapability> encryption,
                                  List<VersionedBlindIndexCapability> blindIndexes,
                                  List<ChallengeDigestCapability> challengeDigests,
                                  List<AccessTokenSigningCapability> signingCapabilities) {
        return codeDigests.stream().flatMap(value -> value.keyReferences().values().stream()).anyMatch(reference::equals)
                || encryption.stream().flatMap(value -> value.keyReferences().values().stream()).anyMatch(reference::equals)
                || blindIndexes.stream().flatMap(value -> value.keyReferences().values().stream()).anyMatch(reference::equals)
                || challengeDigests.stream().map(value -> value.metadata().keyReference()).anyMatch(reference::equals)
                || signingCapabilities.stream().map(AccessTokenSigningCapability::snapshot)
                        .map(value -> value.activeKeyId()).anyMatch(reference::equals);
    }
}
