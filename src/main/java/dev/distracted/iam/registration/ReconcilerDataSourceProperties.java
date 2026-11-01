package dev.distracted.iam.registration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.registration.reconciler")
public record ReconcilerDataSourceProperties(String jdbcUrl, String username, String password) {
    public ReconcilerDataSourceProperties {
        if (blank(jdbcUrl) || blank(username) || blank(password)) {
            throw new RegistrationException("registration_reconciler_configuration_missing");
        }
    }

    void verifyDistinct(String runtimeUsername, String runtimePassword) {
        if (username.equals(runtimeUsername) || password.equals(runtimePassword)) {
            throw new RegistrationException("registration_reconciler_authority_shared");
        }
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }
}
