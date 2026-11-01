package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OnboardingReadyPayloadTest {
    @ParameterizedTest
    @ValueSource(strings = {
        "person@example.invalid", "+15551234567", "credential-canary-value",
        "authorization-code-canary", "refresh-token-canary", "idn_globalidentitycanary"
    })
    void rejectsPrivateOrGlobalIdentifiersWithoutEchoingThem(String canary) {
        assertThatThrownBy(() -> new OnboardingReadyPayload("dutch-development", canary,
                "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining(canary);
    }

    @ParameterizedTest
    @ValueSource(strings = {"RECONCILIATION", "FIRST_ACTIVATION"})
    void acceptsRegisteredReasons(String reason) {
        new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, reason, 1);
    }

    @org.junit.jupiter.api.Test
    void rejectsNullVersionsReasonsAndEnvelopeSemanticMismatches() {
        assertThatThrownBy(() -> new OnboardingReadyPayload(null, "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 0, "FIRST_ACTIVATION", 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, "UNKNOWN", 1)).isInstanceOf(IllegalArgumentException.class);

        var payload = new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 1);
        assertInvalidEnvelope(payload, "wrong.event", "act_abcdefghijklmnop", 1, "dutch-development");
        assertInvalidEnvelope(payload, "iam.app-subject.onboarding-ready.v1", "act_otherabcdefghijkl", 1,
                "dutch-development");
        assertInvalidEnvelope(payload, "iam.app-subject.onboarding-ready.v1", "act_abcdefghijklmnop", 2,
                "dutch-development");
        assertInvalidEnvelope(payload, "iam.app-subject.onboarding-ready.v1", "act_abcdefghijklmnop", 1,
                "midas-development");
        assertThatThrownBy(() -> new OutboxEvent("evt_abcdefghijklmnop",
                "iam.app-subject.onboarding-ready.v1", 2, Instant.EPOCH, "iam", "test", "APP_ONBOARDING",
                payload.activationId(), 1, new CorrelationId("cor_abcdefghijklmnop"), null,
                payload.appRegistrationId(), payload, "0".repeat(64))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event(payload, "bad", "test", new CorrelationId("cor_abcdefghijklmnop"),
                "0".repeat(64))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event(payload, "evt_abcdefghijklmnop", "invalid",
                new CorrelationId("cor_abcdefghijklmnop"), "0".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event(payload, "evt_abcdefghijklmnop", "test", null, "0".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> event(payload, "evt_abcdefghijklmnop", "test",
                new CorrelationId("cor_abcdefghijklmnop"), "invalid"))
                .isInstanceOf(IllegalArgumentException.class);
        for (var environment : java.util.List.of("development", "test", "staging", "production")) {
            event(payload, "evt_abcdefghijklmnop", environment,
                    new CorrelationId("cor_abcdefghijklmnop"), "0".repeat(64));
        }
        assertThatThrownBy(() -> new OutboxEvent("evt_abcdefghijklmnop",
                "iam.app-subject.onboarding-ready.v1", 1, Instant.EPOCH, "other", "test", "APP_ONBOARDING",
                payload.activationId(), 1, new CorrelationId("cor_abcdefghijklmnop"), null,
                payload.appRegistrationId(), payload, "0".repeat(64))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OutboxEvent("evt_abcdefghijklmnop",
                "iam.app-subject.onboarding-ready.v1", 1, Instant.EPOCH, "iam", "test", "OTHER",
                payload.activationId(), 1, new CorrelationId("cor_abcdefghijklmnop"), null,
                payload.appRegistrationId(), payload, "0".repeat(64))).isInstanceOf(IllegalArgumentException.class);
    }

    private static void assertInvalidEnvelope(
            OnboardingReadyPayload payload, String type, String aggregateId, long version, String destination) {
        assertThatThrownBy(() -> new OutboxEvent("evt_abcdefghijklmnop", type, 1, Instant.EPOCH, "iam", "test",
                "APP_ONBOARDING", aggregateId, version, new CorrelationId("cor_abcdefghijklmnop"), null,
                destination, payload,
                "0".repeat(64))).isInstanceOf(IllegalArgumentException.class);
    }

    private static OutboxEvent event(OnboardingReadyPayload payload, String eventId, String environment,
            CorrelationId correlationId, String fingerprint) {
        return new OutboxEvent(eventId, "iam.app-subject.onboarding-ready.v1", 1, Instant.EPOCH, "iam",
                environment, "APP_ONBOARDING", payload.activationId(), payload.onboardingVersion(), correlationId,
                null, payload.appRegistrationId(), payload, fingerprint);
    }
}
