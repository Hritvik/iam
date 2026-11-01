package dev.distracted.iam.messaging;

import dev.distracted.iam.messaging.adapter.jdbc.JdbcOnboardingIntentWriter;
import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.OutboxRelayRepository;
import dev.distracted.iam.messaging.relay.OutboxTransport;
import dev.distracted.iam.messaging.relay.RelaySettings;
import dev.distracted.iam.messaging.relay.adapter.jdbc.JdbcOutboxRelayRepository;
import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotQuery;
import dev.distracted.iam.messaging.snapshot.adapter.jdbc.JdbcOnboardingSnapshotQuery;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
        name = "iam.messaging.enabled", havingValue = "true")
public class MessagingApplicationConfiguration {
    @Bean OnboardingIntentWriter onboardingIntentWriter(JdbcTemplate jdbc) {
        return new JdbcOnboardingIntentWriter(jdbc);
    }

    @Bean OnboardingSnapshotQuery onboardingSnapshotQuery(JdbcTemplate jdbc) {
        return new JdbcOnboardingSnapshotQuery(jdbc);
    }

    @Bean @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
            name = "iam.messaging.relay.enabled", havingValue = "true")
    org.springframework.jdbc.core.JdbcTemplate relayJdbcTemplate(
            @Value("${iam.messaging.relay.jdbc-url}") String url,
            @Value("${iam.messaging.relay.username}") String username,
            @Value("${iam.messaging.relay.password}") String password) {
        return new org.springframework.jdbc.core.JdbcTemplate(
                new org.springframework.jdbc.datasource.DriverManagerDataSource(url, username, password));
    }

    @Bean @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
            name = "iam.messaging.relay.enabled", havingValue = "true")
    OutboxRelayRepository outboxRelayRepository(
            @org.springframework.beans.factory.annotation.Qualifier("relayJdbcTemplate")
            org.springframework.jdbc.core.JdbcTemplate relay) {
        return new JdbcOutboxRelayRepository(relay);
    }

    @Bean @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
            name = "iam.messaging.relay.enabled", havingValue = "true")
    OnboardingRelay onboardingRelay(OutboxRelayRepository repository, OutboxTransport transport,
            @Value("${iam.messaging.relay.owner:iam-relay-1}") String owner,
            @Value("${iam.messaging.relay.lease-seconds:30}") int leaseSeconds,
            @Value("${iam.messaging.relay.batch-limit:50}") int batchLimit,
            @Value("${iam.messaging.relay.maximum-attempts:5}") int maximumAttempts) {
        return new OnboardingRelay(repository, transport,
                new RelaySettings(owner, leaseSeconds, batchLimit, maximumAttempts), Clock.systemUTC());
    }
}
