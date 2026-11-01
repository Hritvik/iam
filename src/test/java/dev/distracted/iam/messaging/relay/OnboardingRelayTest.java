package dev.distracted.iam.messaging.relay;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class OnboardingRelayTest {
    private static final Instant NOW = Instant.parse("2026-10-30T00:00:00Z");
    private static final RelaySettings SETTINGS = new RelaySettings("relay-1", 30, 10, 2);

    @Test void publishesThenAcknowledgesAndNeverAcknowledgesAFailedPublish() {
        var repository = new FakeRepository(List.of(delivery("evt_012345678901234567", 1)));
        var transport = new RecordingTransport(false);
        var outcome = new OnboardingRelay(repository, transport, SETTINGS, clock()).drainOnce();

        assertThat(outcome).isEqualTo(new RelayOutcome(1, 1, 1, 0));
        assertThat(repository.acknowledged).containsExactly("evt_012345678901234567");
        assertThat(repository.quarantined).isEmpty();
    }

    @Test void aFailedPublishLeavesTheDeliveryLeasedForRedelivery() {
        var repository = new FakeRepository(List.of(delivery("evt_012345678901234567", 1)));
        var transport = new RecordingTransport(true);
        var outcome = new OnboardingRelay(repository, transport, SETTINGS, clock()).drainOnce();

        assertThat(outcome).isEqualTo(new RelayOutcome(1, 0, 0, 0));
        assertThat(repository.acknowledged).isEmpty();
        assertThat(repository.quarantined).isEmpty();
    }

    @Test void exhaustedRetriesAndNonRetryableFailuresQuarantine() {
        var exhausted = new FakeRepository(List.of(delivery("evt_012345678901234567", SETTINGS.maximumAttempts())));
        new OnboardingRelay(exhausted, new RecordingTransport(true), SETTINGS, clock()).drainOnce();
        assertThat(exhausted.quarantined).containsExactly("evt_012345678901234567:RETRY_EXHAUSTED",
                "evt_012345678901234567:audit:RETRY_EXHAUSTED");

        var nonRetryable = new FakeRepository(List.of(delivery("evt_112345678901234567", 1)));
        new OnboardingRelay(nonRetryable, envelope -> {
            throw new NonRetryableTransportException();
        }, SETTINGS, clock()).drainOnce();
        assertThat(nonRetryable.quarantined).containsExactly("evt_112345678901234567:NON_RETRYABLE_FAILURE",
                "evt_112345678901234567:audit:NON_RETRYABLE_FAILURE");
    }

    private static Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }

    private static ClaimedDelivery delivery(String eventId, int attempt) {
        return new ClaimedDelivery(eventId, "dutch-ums-onboarding", attempt, 1);
    }

    private static final class RecordingTransport implements OutboxTransport {
        private final boolean fail;
        RecordingTransport(boolean fail) { this.fail = fail; }
        @Override public void publish(OutboxEnvelope envelope) {
            if (fail) throw new TransportException();
        }
    }

    private static final class FakeRepository implements OutboxRelayRepository {
        final List<ClaimedDelivery> claimed;
        final List<String> acknowledged = new ArrayList<>();
        final List<String> quarantined = new ArrayList<>();
        FakeRepository(List<ClaimedDelivery> claimed) { this.claimed = claimed; }
        @Override public List<ClaimedDelivery> claim(String o, Instant n, int s, int l) { return claimed; }
        @Override public Optional<OutboxEnvelope> event(String eventId) {
            return Optional.of(new OutboxEnvelope(eventId, "iam.app-subject.onboarding-ready.v1", 1, NOW, "iam",
                    "development", "APP_ONBOARDING", "act_012345678901234567", 1, "cor_0123456789012345",
                    null, "dutch-development", "{}", "a".repeat(64)));
        }
        @Override public boolean acknowledge(String e, String d, String o, long v, Instant n) {
            acknowledged.add(e);
            return true;
        }
        @Override public boolean quarantine(String e, String d, String o, long v, String r, Instant n) {
            quarantined.add(e + ":" + r);
            return true;
        }
        @Override public void appendQuarantineAudit(String auditId, String eventId, String correlationId,
                                                    String reasonCode, Instant occurredAt) {
            quarantined.add(eventId + ":audit:" + reasonCode);
        }
    }
}
