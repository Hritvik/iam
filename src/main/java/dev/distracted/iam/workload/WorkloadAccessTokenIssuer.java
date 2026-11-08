package dev.distracted.iam.workload;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import dev.distracted.iam.token.AccessTokenMaterialGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Issues short-lived {@code workload_access} v1 tokens for one registered workload binding.
 *
 * <p>There is no human subject and no confirmation key: a workload token can only act for its own
 * registered application, audience and scopes.
 */
public final class WorkloadAccessTokenIssuer {
    private static final Pattern SCOPE = Pattern.compile("^[a-z][a-z0-9:_-]{0,63}$");
    private static final int MINIMUM_LIFETIME_SECONDS = 60;
    private static final int MAXIMUM_LIFETIME_SECONDS = 900;

    private final String issuer;
    private final int lifetimeSeconds;
    private final List<WorkloadIdentityProperties.Binding> bindings;
    private final ECKey signingKey;
    private final AccessTokenMaterialGenerator material;
    private final Clock clock;

    public WorkloadAccessTokenIssuer(
            WorkloadIdentityProperties properties,
            AccessTokenMaterialGenerator material,
            Clock clock) {
        this.issuer = WorkloadKeys.requireHttpsIssuer(properties.issuer());
        this.lifetimeSeconds = lifetime(properties.lifetimeSeconds());
        this.bindings = validateBindings(properties.bindings());
        this.signingKey = WorkloadKeys.signingKey(Objects.requireNonNull(properties.signing()));
        this.material = Objects.requireNonNull(material);
        this.clock = Objects.requireNonNull(clock);
    }

    public String issuer() {
        return issuer;
    }

    public int lifetimeSeconds() {
        return lifetimeSeconds;
    }

    public String issue(String workloadId, String audience, String scope) {
        var binding = bindings.stream()
                .filter(candidate -> candidate.workloadId().equals(workloadId))
                .findFirst()
                .orElseThrow(() -> new WorkloadAccessTokenException("workload_unregistered"));
        WorkloadKeys.requireWorkloadId(workloadId);
        if (audience == null || !binding.audiences().contains(audience)) {
            throw new WorkloadAccessTokenException("workload_audience_not_allowed");
        }
        var canonicalScope = canonicalScope(scope);
        if (canonicalScope.isEmpty() || !binding.scopes().containsAll(Arrays.asList(canonicalScope.split(" ")))) {
            throw new WorkloadAccessTokenException("workload_scope_not_allowed");
        }
        var now = Instant.now(clock).getEpochSecond();
        var expiry = Math.addExact(now, lifetimeSeconds);
        var jti = material.nextJti();
        if (jti == null || !jti.matches("^[A-Za-z0-9_-]{16,128}$")) {
            throw new WorkloadAccessTokenException("workload_material_unavailable");
        }

        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("at+jwt"))
                .keyID(signingKey.getKeyID())
                .build();
        var claims = new LinkedHashMap<String, Object>();
        claims.put("iss", issuer);
        claims.put("sub", workloadId);
        claims.put("aud", audience);
        claims.put("iat", now);
        claims.put("exp", expiry);
        claims.put("jti", jti);
        claims.put("client_id", binding.clientId());
        claims.put("token_profile", "workload_access");
        claims.put("token_version", 1);
        claims.put("subject_kind", "workload");
        claims.put("scope", canonicalScope);
        claims.put("app_id", binding.appRegistrationId());
        claims.put("security_version", 1);
        try {
            var object = new JWSObject(header, new Payload(claims));
            object.sign(new ECDSASigner(signingKey));
            return object.serialize();
        } catch (Exception exception) {
            throw new WorkloadAccessTokenException("workload_token_signing_failed", exception);
        }
    }

    private static String canonicalScope(String value) {
        if (value == null) {
            throw new WorkloadAccessTokenException("workload_scope_invalid");
        }
        var values = new ArrayList<String>();
        for (var item : value.split(" ")) {
            if (!SCOPE.matcher(item).matches() || values.contains(item)) {
                throw new WorkloadAccessTokenException("workload_scope_invalid");
            }
            values.add(item);
        }
        if (values.size() > 32) {
            throw new WorkloadAccessTokenException("workload_scope_invalid");
        }
        values.sort(String::compareTo);
        return String.join(" ", values);
    }

    private static int lifetime(Integer configured) {
        var value = configured == null ? 300 : configured;
        if (value < MINIMUM_LIFETIME_SECONDS || value > MAXIMUM_LIFETIME_SECONDS) {
            throw new WorkloadAccessTokenException("workload_lifetime_invalid");
        }
        return value;
    }

    private static List<WorkloadIdentityProperties.Binding> validateBindings(
            List<WorkloadIdentityProperties.Binding> configured) {
        if (configured == null || configured.isEmpty()) {
            throw new WorkloadAccessTokenException("workload_bindings_missing");
        }
        var result = new ArrayList<WorkloadIdentityProperties.Binding>();
        for (var binding : configured) {
            WorkloadKeys.requireWorkloadId(binding.workloadId());
            WorkloadKeys.requireAppId(binding.appRegistrationId(), "workload_app_id_invalid");
            WorkloadKeys.requireClientId(binding.clientId(), "workload_client_id_invalid");
            if (binding.audiences() == null || binding.audiences().isEmpty()
                    || binding.scopes() == null || binding.scopes().isEmpty()) {
                throw new WorkloadAccessTokenException("workload_binding_invalid");
            }
            result.add(new WorkloadIdentityProperties.Binding(binding.workloadId(), binding.appRegistrationId(),
                    binding.clientId(), List.copyOf(binding.audiences()), List.copyOf(binding.scopes())));
        }
        return List.copyOf(result);
    }
}
