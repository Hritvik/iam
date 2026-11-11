package dev.distracted.iam.authorization.refresh;

import dev.distracted.iam.authorization.adapter.jdbc.JdbcRefreshTokenRepository;
import java.security.SecureRandom;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/** Wires native refresh material and persistence when the refresh grant is enabled. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.refresh.enabled", havingValue = "true")
public class RefreshTokenConfiguration {
    @Bean
    RefreshTokenMaterialGenerator refreshTokenMaterialGenerator() {
        return new SecureRefreshTokenMaterialGenerator(new SecureRandom());
    }

    @Bean
    RefreshTokenRepository refreshTokenRepository(JdbcTemplate jdbc) {
        return new JdbcRefreshTokenRepository(jdbc);
    }
}
