package dev.distracted.iam.messaging.relay;

import java.time.Clock;
import java.util.Objects;

public final class OnboardingRelay {
    private final OutboxRelayRepository repository;
    private final OutboxTransport transport;
    private final RelaySettings settings;
    private final Clock clock;

    public OnboardingRelay(OutboxRelayRepository repository, OutboxTransport transport, RelaySettings settings,
                           Clock clock) {
        this.repository = Objects.requireNonNull(repository);
        this.transport = Objects.requireNonNull(transport);
        this.settings = Objects.requireNonNull(settings);
        this.clock = Objects.requireNonNull(clock);
    }

    public RelayOutcome drainOnce() {
        var now = clock.instant();
        var claimed = repository.claim(settings.owner(), now, settings.leaseSeconds(), settings.batchLimit());
        int published = 0;
        int acknowledged = 0;
        int quarantined = 0;
        for (var delivery : claimed) {
            var envelope = repository.event(delivery.eventId()).orElse(null);
            if (envelope == null) continue;
            try {
                transport.publish(envelope);
                published++;
            } catch (NonRetryableTransportException exception) {
                if (repository.quarantine(delivery.eventId(), delivery.destinationName(), settings.owner(),
                        delivery.version(), "NON_RETRYABLE_FAILURE", clock.instant())) {
                    repository.appendQuarantineAudit(auditId(), delivery.eventId(), envelope.correlationId(),
                            "NON_RETRYABLE_FAILURE", clock.instant());
                    quarantined++;
                }
                continue;
            } catch (TransportException exception) {
                if (delivery.attemptCount() >= settings.maximumAttempts()) {
                    if (repository.quarantine(delivery.eventId(), delivery.destinationName(), settings.owner(),
                            delivery.version(), "RETRY_EXHAUSTED", clock.instant())) {
                        repository.appendQuarantineAudit(auditId(), delivery.eventId(), envelope.correlationId(),
                                "RETRY_EXHAUSTED", clock.instant());
                        quarantined++;
                    }
                }
                continue;
            }
            if (repository.acknowledge(delivery.eventId(), delivery.destinationName(), settings.owner(),
                    delivery.version(), clock.instant())) acknowledged++;
        }
        return new RelayOutcome(claimed.size(), published, acknowledged, quarantined);
    }

    private String auditId() {
        var bytes = new byte[18];
        new java.security.SecureRandom().nextBytes(bytes);
        return "aud_" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
