package dev.distracted.iam.messaging.relay.transport;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.messaging.relay.ClaimedDelivery;
import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.OutboxEnvelope;
import dev.distracted.iam.messaging.relay.OutboxRelayRepository;
import dev.distracted.iam.messaging.relay.RelaySettings;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class RelaySchedulerTest {
    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");

    @Test
    void recordsClaimedPublishedAcknowledgedAndQuarantinedOutcomes() {
        var repository = new FixedRepository();
        var relay = new OnboardingRelay(repository, envelope -> { },
                new RelaySettings("relay-1", 30, 10, 2), Clock.fixed(NOW, ZoneOffset.UTC));
        var registry = new SimpleMeterRegistry();

        new RelayScheduler(relay, registry).drain();

        assertThat(registry.get("iam.relay.deliveries").tag("outcome", "claimed").counter().count())
                .isEqualTo(1.0);
        assertThat(registry.get("iam.relay.deliveries").tag("outcome", "published").counter().count())
                .isEqualTo(1.0);
        assertThat(registry.get("iam.relay.deliveries").tag("outcome", "acknowledged").counter().count())
                .isEqualTo(1.0);
        assertThat(registry.get("iam.relay.deliveries").tag("outcome", "quarantined").counter().count())
                .isZero();
    }

    @Test
    void aRepositoryFailureDoesNotEscapeTheScheduledDrain() {
        var failing = new OutboxRelayRepository() {
            @Override public List<ClaimedDelivery> claim(String o, Instant n, int s, int l) {
                throw new IllegalStateException("database unavailable");
            }

            @Override public Optional<OutboxEnvelope> event(String eventId) {
                return Optional.empty();
            }

            @Override public boolean acknowledge(String e, String d, String o, long v, Instant n) {
                return false;
            }

            @Override public boolean quarantine(String e, String d, String o, long v, String r, Instant n) {
                return false;
            }

            @Override public void appendQuarantineAudit(String a, String e, String c, String r, Instant t) {
            }
        };
        var relay = new OnboardingRelay(failing, envelope -> { },
                new RelaySettings("relay-1", 30, 10, 2), Clock.fixed(NOW, ZoneOffset.UTC));

        new RelayScheduler(relay, new SimpleMeterRegistry()).drain();
    }

    private static final class FixedRepository implements OutboxRelayRepository {
        @Override public List<ClaimedDelivery> claim(String owner, Instant now, int lease, int limit) {
            return List.of(new ClaimedDelivery("evt_0123456789abcdef", "dutch-ums-onboarding", 1, 1));
        }

        @Override public Optional<OutboxEnvelope> event(String eventId) {
            return Optional.of(new OutboxEnvelope(eventId, "iam.app-subject.onboarding-ready.v1", 1, NOW,
                    "iam", "development", "APP_ONBOARDING", "act_0123456789abcdef", 1,
                    "cor_0123456789abcdef", null, "dutch-development", "{}", "a".repeat(64)));
        }

        @Override public boolean acknowledge(String e, String d, String o, long v, Instant n) {
            return true;
        }

        @Override public boolean quarantine(String e, String d, String o, long v, String r, Instant n) {
            return true;
        }

        @Override public void appendQuarantineAudit(String a, String e, String c, String r, Instant t) {
        }
    }
}
