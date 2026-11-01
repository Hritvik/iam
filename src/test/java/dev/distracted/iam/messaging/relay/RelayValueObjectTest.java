package dev.distracted.iam.messaging.relay;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class RelayValueObjectTest {
    @Test void settingsRejectOutOfRangeOwnerLeaseBatchAndAttempts() {
        assertThatThrownBy(() -> new RelaySettings("bad owner!", 30, 10, 5))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RelaySettings("relay-1", 0, 10, 5))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RelaySettings("relay-1", 901, 10, 5))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RelaySettings("relay-1", 30, 0, 5))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RelaySettings("relay-1", 30, 1001, 5))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RelaySettings("relay-1", 30, 10, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void envelopeRequiresItsIdentifyingFields() {
        assertThatThrownBy(() -> new OutboxEnvelope(null, "type", 1, java.time.Instant.now(), "iam", "development",
                "APP_ONBOARDING", "act_012345678901234567", 1, "cor_0123456789012345", null,
                "dutch-development", "{}", "a".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OutboxEnvelope("evt_012345678901234567", "type", 1, java.time.Instant.now(),
                "iam", "development", "APP_ONBOARDING", "act_012345678901234567", 1,
                "cor_0123456789012345", null, "dutch-development", null, "a".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
