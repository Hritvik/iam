package dev.distracted.iam.token.adapter.jdbc;

import dev.distracted.iam.token.AuthorizationServerIssuerAuthority;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.token.enabled", havingValue = "true")
@ConditionalOnProperty(name = "iam.token.issuer-authority.enabled", havingValue = "true", matchIfMissing = true)
public class TokenIssuerAuthorityConfiguration {
    @Bean AuthorizationServerIssuerAuthority authorizationServerIssuerAuthority(JdbcTemplate jdbc) {
        return new JdbcAuthorizationServerIssuerAuthority(jdbc);
    }
}
