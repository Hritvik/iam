package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Instant;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PersistenceIdentifierTest {
    @ParameterizedTest
    @ValueSource(strings = {
        "person@example.invalid", "+15551234567", "credential-canary-value",
        "authorization-code-canary", "refresh-token-canary", "idn_globalidentitycanary"
    })
    void rejectsCanariesFromCorrelationCausationEventAndAuditIdentifiersWithoutEcho(String canary) {
        assertThatThrownBy(() -> new CorrelationId(canary)).hasMessageNotContaining(canary);
        assertThatThrownBy(() -> new CausationId(canary)).hasMessageNotContaining(canary);
        assertThatThrownBy(() -> new AuditFact(canary, "OUTBOX_EVENT_RECORDED", "EVENT",
                "evt_abcdefghijklmnop", "SUCCEEDED", new CorrelationId("cor_abcdefghijklmnop"), null,
                "evt_abcdefghijklmnop", null, Instant.EPOCH)).hasMessageNotContaining(canary);
    }

    @org.junit.jupiter.api.Test
    void acceptsGeneratedIdentifiersAndOnlyPristineInitialDelivery() {
        assertThatCode(() -> new CorrelationId("cor_abcdefghijklmnop")).doesNotThrowAnyException();
        assertThatCode(() -> new CausationId("cau_abcdefghijklmnop")).doesNotThrowAnyException();
        assertThatCode(() -> new InitialDelivery(
                "evt_abcdefghijklmnop", Instant.EPOCH)).doesNotThrowAnyException();
        assertThatThrownBy(() -> new InitialDelivery(null, Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new InitialDelivery("bad", Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new InitialDelivery("evt_abcdefghijklmnop", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @org.junit.jupiter.api.Test
    void validatesEveryAuditSemanticVariant() {
        var correlation = new CorrelationId("cor_abcdefghijklmnop");
        var eventId = "evt_abcdefghijklmnop";
        assertThatCode(() -> new AuditFact("aud_abcdefghijklmnop", "OUTBOX_DELIVERY_QUARANTINED", "EVENT",
                eventId, "FAILED", correlation, new CausationId("cau_abcdefghijklmnop"), eventId,
                "NON_RETRYABLE_FAILURE", Instant.EPOCH)).doesNotThrowAnyException();
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", "OUTBOX_EVENT_RECORDED", "EVENT",
                eventId, "SUCCEEDED", null, null, eventId, null, Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", "OUTBOX_EVENT_RECORDED", "EVENT",
                eventId, "SUCCEEDED", correlation, null, eventId, null, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", "OUTBOX_EVENT_RECORDED", "EVENT",
                eventId, "SUCCEEDED", correlation, null, "bad", null, Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", "OUTBOX_EVENT_RECORDED", "EVENT",
                "evt_otherabcdefghijkl", "SUCCEEDED", correlation, null, eventId, null, Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", "UNKNOWN", "EVENT", eventId,
                "SUCCEEDED", correlation, null, eventId, null, Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", "OUTBOX_DELIVERY_QUARANTINED", "EVENT",
                eventId, "FAILED", correlation, null, eventId, "UNKNOWN", Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
