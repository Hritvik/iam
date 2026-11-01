package dev.distracted.iam.identity;

import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import dev.distracted.iam.platform.persistence.JdbcAuditFactRepository;
import dev.distracted.iam.platform.persistence.SpringTransactionRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration(proxyBeanMethods = false)
public class IdentityApplicationConfiguration {
    @Bean IdentityMaterialGenerator identityMaterialGenerator() { return new SecureIdentityMaterialGenerator(); }
    @Bean EvidenceMaterialGenerator evidenceMaterialGenerator() { return new SecureEvidenceMaterialGenerator(); }
    @Bean IdentifierNormalizer identifierNormalizer() { return new IdentifierNormalizer(); }
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnBean(JdbcTemplate.class)
    IdentityEvidenceService identityEvidenceService(JdbcTemplate jdbc, EvidenceMaterialGenerator materials) {
        return new IdentityEvidenceService(jdbc, materials);
    }

    public static IdentityService assembleIdentityService(JdbcTemplate jdbc, PlatformTransactionManager transactionManager,
            IdentifierNormalizer normalizer, StructuredIdentifierEncryptionCapability encryption,
            VersionedBlindIndexCapability blindIndexes, ChallengeDigestCapability digests,
            IdentityMaterialGenerator materials, ChallengeDeliveryPort delivery, Environment environment) {
        var runtimeEnvironment = java.util.Arrays.stream(environment.getActiveProfiles())
                .map(profile -> "production-like".equals(profile) ? "production" : profile)
                .filter(java.util.Set.of("development", "test", "staging", "production")::contains)
                .findFirst().orElseThrow(() -> new IllegalStateException("identity_environment_missing"));
        return new IdentityService(jdbc, new SpringTransactionRunner(new TransactionTemplate(transactionManager)),
                new JdbcAuditFactRepository(jdbc), normalizer, encryption, blindIndexes, digests,
                materials, delivery, runtimeEnvironment);
    }

    @Bean
    @org.springframework.context.annotation.Profile("development | test")
    @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
            name = "iam.fixtures.deterministic-identity.enabled", havingValue = "true")
    IdentityService deterministicFixtureIdentityService(JdbcTemplate jdbc,
            PlatformTransactionManager transactionManager, IdentifierNormalizer normalizer,
            StructuredIdentifierEncryptionCapability encryption, VersionedBlindIndexCapability blindIndexes,
            ChallengeDigestCapability digests, IdentityMaterialGenerator materials,
            ChallengeDeliveryPort delivery, Environment environment) {
        return assembleIdentityService(jdbc, transactionManager, normalizer, encryption, blindIndexes, digests,
                materials, delivery, environment);
    }
}
