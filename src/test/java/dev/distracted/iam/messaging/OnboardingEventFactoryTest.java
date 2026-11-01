package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class OnboardingEventFactoryTest {
    private final OnboardingEventFactory factory = new OnboardingEventFactory();
    private static final String APP = "dutch-development";
    private static final String SUBJECT = "aps_0123456789012345678901ab";
    private static final String ACTIVATION = "act_012345678901234567";

    @Test void buildsTheExactClosedAppScopedPayload() {
        var payload = factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "FIRST_ACTIVATION");

        @SuppressWarnings("unchecked")
        Map<String, Object> value = new ObjectMapper().readValue(payload.json(), Map.class);
        assertThat(value).containsOnlyKeys("appRegistrationId", "appSubject", "activationId", "activationState",
                "activationVersion", "onboardingReason", "onboardingVersion", "requiredProfileState");
        assertThat(value).containsEntry("appRegistrationId", APP).containsEntry("appSubject", SUBJECT)
                .containsEntry("activationState", "ACTIVE").containsEntry("requiredProfileState", "PROFILE_REQUIRED")
                .containsEntry("onboardingReason", "FIRST_ACTIVATION");
        assertThat(payload.json()).doesNotContain("hid_", "identity", "identifier", "token");
        assertThat(payload.fingerprint()).matches("^[0-9a-f]{64}$");
        assertThat(factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "FIRST_ACTIVATION").fingerprint())
                .isEqualTo(payload.fingerprint());
        var canonical = new Rfc8785PayloadFingerprint().fingerprint(new OnboardingReadyPayload(APP, SUBJECT,
                "act_012345678901234567", 2, "FIRST_ACTIVATION", 1));
        assertThat(payload.fingerprint()).isEqualTo(canonical);
    }

    @Test void rejectsPendingActivationsAndUnknownReasons() {
        assertThatThrownBy(() -> factory.create(APP, SUBJECT, ACTIVATION, 1, 0, null))
                .isInstanceOf(OnboardingIntentException.class);
        assertThatThrownBy(() -> factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "OTHER"))
                .isInstanceOf(OnboardingIntentException.class);
    }


}
