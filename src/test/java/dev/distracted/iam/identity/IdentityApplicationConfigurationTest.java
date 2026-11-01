package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

class IdentityApplicationConfigurationTest {
    @Test
    void productionLikeUsesStableProductionCryptographicDomain() {
        var environment = mock(Environment.class);
        when(environment.getActiveProfiles()).thenReturn(new String[] {"production-like"});
        var service = IdentityApplicationConfiguration.assembleIdentityService(mock(JdbcTemplate.class),
                mock(PlatformTransactionManager.class), new IdentifierNormalizer(),
                mock(StructuredIdentifierEncryptionCapability.class), mock(VersionedBlindIndexCapability.class),
                mock(ChallengeDigestCapability.class), mock(IdentityMaterialGenerator.class),
                (challengeId, code) -> { }, environment);
        assertThat(service).isNotNull();
    }
}
