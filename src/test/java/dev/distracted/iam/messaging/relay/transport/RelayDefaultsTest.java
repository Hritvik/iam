package dev.distracted.iam.messaging.relay.transport;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

class RelayDefaultsTest {
    @Test
    void shipsTheUmsRouteAndTheAudienceAsDifferentStrings() {
        try {
            var sources = new YamlPropertySourceLoader().load(
                    "development", new ClassPathResource("application-development.yaml"));
            var environment = new StandardEnvironment();
            sources.forEach(source -> environment.getPropertySources().addLast(source));

            assertThat(environment.resolvePlaceholders(
                    environment.getProperty("iam.messaging.relay.transport.endpoint")))
                    .isEqualTo("https://ums.example.test/internal/v1/iam/events");
            assertThat(environment.resolvePlaceholders(
                    environment.getProperty("iam.messaging.relay.transport.audience")))
                    .isEqualTo("https://ums.example.test/internal/iam/events");
        } catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }
}
