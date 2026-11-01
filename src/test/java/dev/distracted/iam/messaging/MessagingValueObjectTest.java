package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class MessagingValueObjectTest {
    @Test void payloadRequiresJsonAndASha256Fingerprint() {
        assertThatThrownBy(() -> new OnboardingPayload(" ", "a".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingPayload("{}", "short"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void intentRequiresAnEventIdAndPositiveVersion() {
        assertThatThrownBy(() -> new OnboardingIntent("bad", "act_012345678901234567", 1, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingIntent("evt_012345678901234567", "act_012345678901234567", 0, true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void commandRequiresEveryField() {
        assertThatThrownBy(() -> new OnboardingIntentCommand(null, "act_012345678901234567", "dutch-development",
                "aps_0123456789012345678901ab", 2, 1, "FIRST_ACTIVATION", "development",
                "cor_0123456789012345", "{}", "a".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingIntentCommand("evt_012345678901234567", "act_012345678901234567",
                "dutch-development", "aps_0123456789012345678901ab", 2, 1, "FIRST_ACTIVATION", null,
                "cor_0123456789012345", "{}", "a".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void factoryRejectsAnUnknownReasonOrMalformedSubject() {
        var factory = new OnboardingEventFactory();
        assertThatThrownBy(() -> factory.create("dutch-development", "not-a-subject",
                "act_012345678901234567", 2, 1, "FIRST_ACTIVATION"))
                .isInstanceOf(OnboardingIntentException.class);
        assertThatThrownBy(() -> factory.create("dutch-development", "aps_0123456789012345678901ab",
                "act_012345678901234567", 2, 1, "OTHER"))
                .isInstanceOf(OnboardingIntentException.class);
    }
}
