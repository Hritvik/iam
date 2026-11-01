package dev.distracted.iam.registration.adapter.jdbc;

import dev.distracted.iam.registration.ReconciliationResult;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.registration.RegistrationRegistry;
import dev.distracted.iam.registration.ValidatedRegistration;
import java.util.Optional;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcRegistrationRegistry implements RegistrationRegistry {
    private final JdbcTemplate jdbc;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public JdbcRegistrationRegistry(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public ReconciliationResult reconcile(ValidatedRegistration registration) {
        var value = registration.manifest();
        var client = value.client();
        var resource = value.resource();
        var policy = value.securityPolicy();
        var result = jdbc.queryForObject("select public.reconcile_pinned_registration(?,?::smallint,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                String.class, value.appRegistrationId(), value.manifestVersion(), value.displayName(), value.environment(),
                registration.fingerprint(), client.clientId(), client.clientType(), client.browserMode(),
                client.redirectUris().toArray(String[]::new), client.grantTypes().toArray(String[]::new),
                client.pkceMethods().toArray(String[]::new), resource.resourceId(), resource.audience(),
                resource.allowedScopes().toArray(String[]::new), policy.requireDpop(), policy.requiredPkceMethod(),
                policy.requiredActivationEvidence().toArray(String[]::new));
        return ReconciliationResult.valueOf(result);
    }

    @Override public Optional<RegistrationManifest> findByAppId(String id) {
        return canonical().filter(value -> value.appRegistrationId().equals(id));
    }
    @Override public Optional<RegistrationManifest> findByClientId(String id) {
        return canonical().filter(value -> value.client().clientId().equals(id));
    }
    @Override public Optional<RegistrationManifest> findByResourceId(String id) {
        return canonical().filter(value -> value.resource().resourceId().equals(id));
    }
    @Override public Optional<RegistrationManifest> findByAudience(String value) {
        return canonical().filter(registration -> registration.resource().audience().equals(value));
    }
    @Override public Optional<RegistrationManifest> findSoleRegistration() { return canonical(); }

    private Optional<RegistrationManifest> canonical() {
        var json = jdbc.queryForObject("select public.canonical_registration()::text", String.class);
        if (json == null) return Optional.empty();
        try {
            return Optional.of(mapper.readValue(json, RegistrationManifest.class));
        } catch (RuntimeException exception) {
            throw new dev.distracted.iam.registration.RegistrationException(
                    "registration_canonical_result_invalid", exception);
        }
    }
}
