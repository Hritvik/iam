package dev.distracted.iam.messaging.relay.transport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.OutboxTransport;
import dev.distracted.iam.workload.WorkloadAccessTokenIssuer;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class RelayRuntimeConfigurationTest {
    private WorkloadAccessTokenIssuer issuer;

    @BeforeEach
    void setUp() {
        issuer = mock(WorkloadAccessTokenIssuer.class);
        when(issuer.lifetimeSeconds()).thenReturn(300);
    }

    @Test
    void wiresTheHttpTransport() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(OutboxTransport.class);
        });
    }

    @Test
    void failsWhenWorkloadSigningIsUnavailable() {
        new ApplicationContextRunner()
                .withUserConfiguration(RelayRuntimeConfiguration.class)
                .withPropertyValues(relayProperties())
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("relay_workload_signing_unavailable");
                });
    }

    @Test
    void failsWhenTheConsumerEndpointIsMissing() {
        runnerWithout("iam.messaging.relay.transport.endpoint").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("relay_transport_configuration_missing");
        });
    }

    @Test
    void failsOnAnUnboundedTimeout() {
        runnerWith("iam.messaging.relay.transport.request-timeout-ms=90000").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("relay_transport_request_timeout_invalid");
        });
        runnerWith("iam.messaging.relay.transport.connect-timeout-ms=0").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("relay_transport_connect_timeout_invalid");
        });
    }

    @Test
    void wiresTheSchedulerOnlyWhenEnabled() {
        runner()
                .withPropertyValues("iam.messaging.relay.schedule.enabled=true")
                .withBean(OnboardingRelay.class, () -> mock(OnboardingRelay.class))
                .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(RelayScheduler.class);
                });
        runner().run(context -> assertThat(context).doesNotHaveBean(RelayScheduler.class));
    }

    private ApplicationContextRunner runner() {
        return runnerWith();
    }

    private ApplicationContextRunner runnerWithout(String property) {
        var runner = new ApplicationContextRunner()
                .withUserConfiguration(RelayRuntimeConfiguration.class)
                .withBean(WorkloadAccessTokenIssuer.class, () -> issuer);
        for (var value : relayProperties()) {
            if (!value.startsWith(property + "=")) {
                runner = runner.withPropertyValues(value);
            }
        }
        return runner;
    }

    private ApplicationContextRunner runnerWith(String... extra) {
        return new ApplicationContextRunner()
                .withUserConfiguration(RelayRuntimeConfiguration.class)
                .withBean(WorkloadAccessTokenIssuer.class, () -> issuer)
                .withPropertyValues(relayProperties())
                .withPropertyValues(extra);
    }

    private static String[] relayProperties() {
        return new String[] {
            "iam.messaging.relay.enabled=true",
            "iam.messaging.relay.transport.mode=http",
            "iam.messaging.relay.transport.endpoint=https://ums.invalid/internal/v1/iam/events",
            "iam.messaging.relay.transport.workload-id=wl_0123456789abcdefghijklmnop",
            "iam.messaging.relay.transport.audience=https://ums.invalid/internal/v1/iam/events",
            "iam.messaging.relay.transport.scope=ums:onboarding:write",
            "iam.messaging.relay.transport.connect-timeout-ms=2000",
            "iam.messaging.relay.transport.request-timeout-ms=5000"
        };
    }
}
