package dev.distracted.iam.messaging.relay.transport;

import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.RelayOutcome;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Drains the outbox on a fixed delay. Leases make concurrent replicas safe; the counters make
 * retry and quarantine behaviour visible without reading the database.
 */
public final class RelayScheduler {
    private static final Logger LOGGER = LoggerFactory.getLogger(RelayScheduler.class);

    private final OnboardingRelay relay;
    private final Counter claimed;
    private final Counter published;
    private final Counter acknowledged;
    private final Counter quarantined;

    public RelayScheduler(OnboardingRelay relay, MeterRegistry registry) {
        this.relay = Objects.requireNonNull(relay);
        Objects.requireNonNull(registry);
        this.claimed = counter(registry, "claimed");
        this.published = counter(registry, "published");
        this.acknowledged = counter(registry, "acknowledged");
        this.quarantined = counter(registry, "quarantined");
    }

    @Scheduled(
            fixedDelayString = "${iam.messaging.relay.schedule.interval-ms:5000}",
            initialDelayString = "${iam.messaging.relay.schedule.initial-delay-ms:5000}")
    public void drain() {
        final RelayOutcome outcome;
        try {
            outcome = relay.drainOnce();
        } catch (RuntimeException exception) {
            LOGGER.warn("Outbox relay drain failed: {}", exception.getMessage());
            return;
        }
        claimed.increment(outcome.claimed());
        published.increment(outcome.published());
        acknowledged.increment(outcome.acknowledged());
        quarantined.increment(outcome.quarantined());
        if (outcome.claimed() > 0) {
            LOGGER.info("Outbox relay drained: claimed={} published={} acknowledged={} quarantined={}",
                    outcome.claimed(), outcome.published(), outcome.acknowledged(), outcome.quarantined());
        }
    }

    private static Counter counter(MeterRegistry registry, String outcome) {
        return Counter.builder("iam.relay.deliveries")
                .description("Outbox relay delivery outcomes")
                .tag("outcome", outcome)
                .register(registry);
    }
}
