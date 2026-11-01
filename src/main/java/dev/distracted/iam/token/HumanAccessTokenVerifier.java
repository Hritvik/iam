package dev.distracted.iam.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.registration.RegistrationManifest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

public final class HumanAccessTokenVerifier {
    private static final Set<String> HEADER_KEYS = Set.of("typ", "alg", "kid");
    private static final Set<String> CLAIM_KEYS = Set.of("iss", "sub", "aud", "iat", "exp", "jti", "client_id",
            "token_profile", "token_version", "subject_kind", "scope", "app_id", "security_version", "cnf");
    private static final Pattern JTI = Pattern.compile("^[A-Za-z0-9_-]{22,128}$");
    private static final Pattern KEY_ID = Pattern.compile("^[A-Za-z0-9_-]{8,128}$");
    private static final Pattern SCOPE = Pattern.compile("^[a-z][a-z0-9:_-]{0,63}$");
    private final List<ECKey> keys;
    private final Clock clock;
    private final String issuer;
    private final Duration skew;
    private final ObjectMapper mapper = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    public HumanAccessTokenVerifier(List<ECKey> keys, Clock clock, String issuer, Duration skew) {
        this.keys = verifiedKeys(keys);
        this.clock = java.util.Objects.requireNonNull(clock);
        this.issuer = java.util.Objects.requireNonNull(issuer);
        if (skew == null || skew.isNegative() || skew.compareTo(Duration.ofSeconds(60)) > 0 || skew.getNano() != 0) {
            throw new IllegalArgumentException("verification skew is invalid");
        }
        this.skew = skew;
    }

    public VerifiedHumanAccessToken verify(String compact, RegistrationManifest registration, int expectedSecurityVersion) {
        try {
            if (compact == null || compact.length() > 8192 || expectedSecurityVersion < 1) throw invalid();
            var segments = compact.split("\\.", -1);
            if (segments.length != 3) throw invalid();
            @SuppressWarnings("unchecked")
            var rawHeader = mapper.readValue(new Base64URL(segments[0]).decode(), Map.class);
            @SuppressWarnings("unchecked")
            var rawClaims = mapper.readValue(new Base64URL(segments[1]).decode(), Map.class);
            var object = JWSObject.parse(compact);
            var header = object.getHeader();
            var headerJson = header.toJSONObject();
            if (!HEADER_KEYS.equals(rawHeader.keySet()) || !HEADER_KEYS.equals(headerJson.keySet())
                    || !"at+jwt".equals(header.getType().toString())
                    || !JWSAlgorithm.ES256.equals(header.getAlgorithm()) || header.getKeyID() == null) throw invalid();
            var key = keys.stream().filter(candidate -> header.getKeyID().equals(candidate.getKeyID())).findFirst()
                    .orElseThrow(HumanAccessTokenVerifier::invalid);
            if (key.isPrivate() || !object.verify(new ECDSAVerifier(key))) throw invalid();
            @SuppressWarnings("unchecked")
            var claims = rawClaims;
            if (!CLAIM_KEYS.equals(claims.keySet())
                    || !issuer.equals(claims.get("iss"))
                    || !registration.appRegistrationId().equals(claims.get("app_id"))
                    || !registration.client().clientId().equals(claims.get("client_id"))
                    || !registration.resource().audience().equals(claims.get("aud"))
                    || !registration.securityPolicy().requireDpop()
                    || !"human_access".equals(claims.get("token_profile"))
                    || !Integer.valueOf(1).equals(asInteger(claims.get("token_version")))
                    || !"app_subject".equals(claims.get("subject_kind"))
                    || !Integer.valueOf(expectedSecurityVersion).equals(asInteger(claims.get("security_version")))) {
                throw invalid();
            }
            var subject = new AppSubject(asString(claims.get("sub")));
            var scope = asString(claims.get("scope"));
            var scopes = Arrays.asList(scope.split(" ", -1));
            if (scopes.size() > 32 || scopes.stream().anyMatch(value -> !SCOPE.matcher(value).matches())
                    || Set.copyOf(scopes).size() != scopes.size()
                    || !scopes.equals(scopes.stream().sorted().toList())
                    || !registration.resource().allowedScopes().containsAll(scopes)) throw invalid();
            var jti = asString(claims.get("jti"));
            if (!JTI.matcher(jti).matches()) throw invalid();
            var iat = asLong(claims.get("iat"));
            var exp = asLong(claims.get("exp"));
            var now = Instant.now(clock).getEpochSecond();
            if (iat <= 0 || exp - iat < 60 || exp - iat > 900
                    || iat > Math.addExact(now, skew.toSeconds())
                    || exp < Math.subtractExact(now, skew.toSeconds())) throw invalid();
            if (!(claims.get("cnf") instanceof Map<?, ?> confirmation)
                    || !Set.of("jkt").equals(confirmation.keySet())) throw invalid();
            var thumbprint = new DpopKeyThumbprint(asString(confirmation.get("jkt")));
            return new VerifiedHumanAccessToken(subject, registration.appRegistrationId(),
                    registration.client().clientId(), registration.resource().audience(), scope,
                    expectedSecurityVersion, thumbprint, Instant.ofEpochSecond(iat), Instant.ofEpochSecond(exp));
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (Exception exception) {
            throw invalid();
        }
    }

    private static String asString(Object value) {
        if (!(value instanceof String text)) throw invalid();
        return text;
    }

    private static Integer asInteger(Object value) {
        if (!isJsonInteger(value)) throw invalid();
        var exact = exactLong((Number) value);
        if (exact > Integer.MAX_VALUE || exact < Integer.MIN_VALUE) throw invalid();
        return (int) exact;
    }

    private static long asLong(Object value) {
        if (!isJsonInteger(value)) throw invalid();
        return exactLong((Number) value);
    }

    private static boolean isJsonInteger(Object value) {
        return value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long
                || value instanceof java.math.BigInteger;
    }

    private static long exactLong(Number value) {
        try {
            return value instanceof java.math.BigInteger bigInteger ? bigInteger.longValueExact() : value.longValue();
        } catch (ArithmeticException exception) {
            throw invalid();
        }
    }

    private static HumanAccessTokenIssueException invalid() {
        return new HumanAccessTokenIssueException("invalid_context");
    }

    private static List<ECKey> verifiedKeys(List<ECKey> candidates) {
        if (candidates == null || candidates.isEmpty() || candidates.size() > 8) {
            throw new IllegalArgumentException("verification keys are invalid");
        }
        var ids = new java.util.HashSet<String>();
        for (var key : candidates) {
            if (key == null || key.isPrivate() || !Curve.P_256.equals(key.getCurve())
                    || !KeyUse.SIGNATURE.equals(key.getKeyUse())
                    || !JWSAlgorithm.ES256.equals(key.getAlgorithm())
                    || key.getKeyID() == null || !KEY_ID.matcher(key.getKeyID()).matches()
                    || !ids.add(key.getKeyID())) {
                throw new IllegalArgumentException("verification keys are invalid");
            }
        }
        return List.copyOf(candidates);
    }
}
