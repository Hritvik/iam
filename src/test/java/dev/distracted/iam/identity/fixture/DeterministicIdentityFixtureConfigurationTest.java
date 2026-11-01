package dev.distracted.iam.identity.fixture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.TokenSignerCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class DeterministicIdentityFixtureConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(FixtureSafetyConfiguration.class,
                    DeterministicIdentityFixtureConfiguration.class);

    @ParameterizedTest
    @ValueSource(strings = {"", "development", "test", "staging", "production", "production-like"})
    void fixtureGraphIsAbsentWhenOptInIsFalse(String profile) {
        var candidate = profile.isEmpty() ? runner : runner.withPropertyValues("spring.profiles.active=" + profile);
        candidate.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(FixtureChallengeDelivery.class);
            assertThat(context).doesNotHaveBean(DeterministicIdentityFixtureRunner.class);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"staging", "production", "production-like", "prod", "prod-like", "qa",
            "development,production-like", "test,staging", "development,qa", "test,local"})
    void forbiddenAndMixedProfilesRejectOptIn(String profiles) {
        runner.withPropertyValues("spring.profiles.active=" + profiles,
                "iam.fixtures.deterministic-identity.enabled=true").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("fixture_profile_forbidden");
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"development", "test"})
    void allowedProfileStillFailsClosedWhenCapabilitiesAreMissing(String profile) {
        runner.withPropertyValues("spring.profiles.active=" + profile,
                "iam.fixtures.deterministic-identity.enabled=true").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("fixture_encryption_unavailable");
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"development", "test", "development,test"})
    void onlyTheExactAllowedProfileSetsPassTheProfileGuard(String profiles) {
        runner.withPropertyValues("spring.profiles.active=" + profiles,
                "iam.fixtures.deterministic-identity.enabled=true").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("fixture_encryption_unavailable");
                    assertThat(stackTrace(context.getStartupFailure())).doesNotContain("fixture_profile_forbidden");
                });
    }

    @org.junit.jupiter.api.Test
    void springSuppliedCapabilityAmbiguityFailsClosed() {
        runner.withPropertyValues("spring.profiles.active=test",
                        "iam.fixtures.deterministic-identity.enabled=true")
                .withBean("encryptionOne", StructuredIdentifierEncryptionCapability.class,
                        () -> mock(StructuredIdentifierEncryptionCapability.class))
                .withBean("encryptionTwo", StructuredIdentifierEncryptionCapability.class,
                        () -> mock(StructuredIdentifierEncryptionCapability.class))
                .withBean(VersionedBlindIndexCapability.class, () -> mock(VersionedBlindIndexCapability.class))
                .withBean(ChallengeDigestCapability.class, () -> mock(ChallengeDigestCapability.class))
                .withBean(TokenSignerCapability.class, () -> mock(TokenSignerCapability.class))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("fixture_encryption_unavailable");
                });
    }

    private static String stackTrace(Throwable failure) {
        var writer = new java.io.StringWriter();
        failure.printStackTrace(new java.io.PrintWriter(writer));
        return writer.toString();
    }
}
