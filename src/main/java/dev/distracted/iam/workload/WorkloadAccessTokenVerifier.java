package dev.distracted.iam.workload;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import dev.distracted.iam.messaging.snapshot.web.WorkloadPrincipal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Verifies the published {@code workload_access} v1 profile for a resource server. */
public final class WorkloadAccessTokenVerifier {
    private static final Set<String> HEADER_KEYS = Set.of("typ", "alg", "kid");
    private static final Set<String> CLAIM_KEYS = Set.of("iss", "sub", "aud", "iat", "exp", "jti", "client_id",
            "token_profile", "token_version", "subject_kind", "scope", "app_id", "security_version");
    private static final Pattern JTI = Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
    private static final Pattern SCOPE = Pattern.compile("^[a-z][a-z0-9:_-]{0,63}$");
    private static final Pattern WORKLOAD_ID = Pattern.compile("^wl_[A-Za-z0-9_-]{22,128}$");

    private final List<ECKey> keys;
    private final List<WorkloadIdentityProperties.Binding> bindings;
    private final String issuer;
    private final Duration skew;
    private final Clock clock;
    private final ObjectMapper mapper = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    public WorkloadAccessTokenVerifier(WorkloadIdentityProperties properties, Clock clock) {
        this.issuer = WorkloadKeys.requireHttpsIssuer(properties.issuer());
        this.bindings = validateBindings(properties.bindings());
        this.keys = validateKeys(properties.trustedKeys());
        this.skew = skew(properties.skewSeconds());
        this.clock = Objects.requireNonNull(clock);
    }

    public WorkloadPrincipal verify(String compact, String requiredAudience, String requiredScope) {
        try {
            if (compact == null || compact.length() > 8192
                    || requiredAudience == null || requiredScope == null) {
                throw invalid();
            }
            var segments = compact.split("\\.", -1);
            if (segments.length != 3) throw invalid();
            var rawHeader = readObject(new Base64URL(segments[0]).decode());
            var rawClaims = readObject(new Base64URL(segments[1]).decode());
            var object = JWSObject.parse(compact);
            var header = object.getHeader();
            if (!HEADER_KEYS.equals(rawHeader.keySet()) || !HEADER_KEYS.equals(header.toJSONObject().keySet())
                    || !"at+jwt".equals(header.getType().toString())
                    || !JWSAlgorithm.ES256.equals(header.getAlgorithm())
                    || header.getKeyID() == null) throw invalid();
            var key = keys.stream()
                    .filter(candidate -> header.getKeyID().equals(candidate.getKeyID()))
                    .findFirst()
                    .orElseThrow(WorkloadAccessTokenVerifier::invalid);
            if (key.isPrivate() || !object.verify(new ECDSAVerifier(key))) throw invalid();
            if (!CLAIM_KEYS.equals(rawClaims.keySet())
                    || !issuer.equals(rawClaims.get("iss"))
                    || !"workload_access".equals(rawClaims.get("token_profile"))
                    || !Integer.valueOf(1).equals(asInteger(rawClaims.get("token_version")))
                    || !"workload".equals(rawClaims.get("subject_kind"))) {
                throw invalid();
            }

            var workloadId = asString(rawClaims.get("sub"));
            var appId = asString(rawClaims.get("app_id"));
            var clientId = asString(rawClaims.get("client_id"));
            if (!WORKLOAD_ID.matcher(workloadId).matches()) throw invalid();
            WorkloadKeys.requireAppId(appId, "invalid_workload_token");
            WorkloadKeys.requireClientId(clientId, "invalid_workload_token");
            var binding = bindings.stream()
                    .filter(candidate -> candidate.appRegistrationId().equals(appId)
                            && candidate.workloadId().equals(workloadId)
                            && candidate.clientId().equals(clientId))
                    .findFirst()
                    .orElseThrow(WorkloadAccessTokenVerifier::invalid);

            var audience = asString(rawClaims.get("aud"));
            var scopes = canonicalScope(asString(rawClaims.get("scope")));
            if (!binding.audiences().contains(audience) || !binding.scopes().containsAll(scopes)
                    || !scopes.contains(requiredScope) || !requiredAudience.equals(audience)) {
                throw invalid();
            }
            var securityVersion = asInteger(rawClaims.get("security_version"));
            if (securityVersion == null || !securityVersion.equals(binding.securityVersion() == null
                    ? 1 : binding.securityVersion())) throw invalid();
            var jti = asString(rawClaims.get("jti"));
            if (!JTI.matcher(jti).matches()) throw invalid();
            var iat = asLong(rawClaims.get("iat"));
            var exp = asLong(rawClaims.get("exp"));
            var now = Instant.now(clock).getEpochSecond();
            if (iat <= 0 || exp - iat < 60 || exp - iat > 900
                    || iat > Math.addExact(now, skew.toSeconds())
                    || exp < Math.subtractExact(now, skew.toSeconds())) {
                throw invalid();
            }
            return new WorkloadPrincipal(appId, Set.copyOf(scopes), audience);
        } catch (WorkloadAccessTokenException exception) {
            throw exception;
        } catch (Exception exception) {
            throw invalid();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readObject(byte[] value) throws Exception {
        return mapper.readValue(value, Map.class);
    }

    private static List<String> canonicalScope(String scope) {
        var values = Arrays.asList(scope.split(" ", -1));
        if (values.isEmpty() || values.size() > 32
                || values.stream().anyMatch(value -> !SCOPE.matcher(value).matches())
                || new LinkedHashSet<>(values).size() != values.size()
                || !values.equals(values.stream().sorted().toList())) {
            throw invalid();
        }
        return values;
    }

    private static String asString(Object value) {
        if (!(value instanceof String text)) throw invalid();
        return text;
    }

    private static Integer asInteger(Object value) {
        if (!(value instanceof Number number)) throw invalid();
        var exact = exactLong(number);
        if (exact > Integer.MAX_VALUE || exact < Integer.MIN_VALUE) throw invalid();
        return (int) exact;
    }

    private static long asLong(Object value) {
        if (!(value instanceof Number number)) throw invalid();
        return exactLong(number);
    }

    private static long exactLong(Number number) {
        if (number instanceof Integer || number instanceof Long || number instanceof Short) {
            return number.longValue();
        }
        throw invalid();
    }

    private static Duration skew(Integer configured) {
        var seconds = configured == null ? 30 : configured;
        if (seconds < 0 || seconds > 60) throw new WorkloadAccessTokenException("workload_skew_invalid");
        return Duration.ofSeconds(seconds);
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
                    || binding.scopes() == null || binding.scopes().isEmpty()
                    || (binding.securityVersion() != null && binding.securityVersion() < 1)) {
                throw new WorkloadAccessTokenException("workload_binding_invalid");
            }
            result.add(binding);
        }
        return List.copyOf(result);
    }

    private static List<ECKey> validateKeys(List<WorkloadIdentityProperties.TrustedKey> configured) {
        if (configured == null || configured.isEmpty()) {
            throw new WorkloadAccessTokenException("workload_trust_keys_missing");
        }
        var result = new ArrayList<ECKey>();
        for (var trusted : configured) {
            var key = WorkloadKeys.trustedKey(trusted);
            if (key.isPrivate()) throw new WorkloadAccessTokenException("workload_trust_key_invalid");
            result.add(key);
        }
        return List.copyOf(result);
    }

    private static WorkloadAccessTokenException invalid() {
        return new WorkloadAccessTokenException("invalid_workload_token");
    }
}
