package dev.distracted.iam.dpop;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import dev.distracted.iam.token.AuthorizationServerIssuerAuthority;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

public final class DpopProofVerifier implements DpopProofValidation {
    private static final Set<String> HEADER_KEYS = Set.of("typ", "alg", "jwk");
    private static final Set<String> TOKEN_CLAIMS = Set.of("htm", "htu", "iat", "jti", "nonce");
    private static final Set<String> CHALLENGE_CLAIMS = Set.of("htm", "htu", "iat", "jti");
    private static final Pattern METHOD = Pattern.compile("^[A-Z]{3,16}$");
    private static final Pattern JTI = Pattern.compile("^[A-Za-z0-9_-]{22,128}$");
    private static final Pattern NONCE = Pattern.compile("^[A-Za-z0-9_-]{32,128}$");
    private final Clock clock;
    private final int maximumAgeSeconds;
    private final int maximumFutureSkewSeconds;
    private final int maximumCompactLength;
    private final String tokenTarget;
    private final ObjectMapper mapper = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    public DpopProofVerifier(Clock clock, int maximumAgeSeconds, int maximumCompactLength,
                             AuthorizationServerIssuerAuthority issuerAuthority) {
        this(clock, maximumAgeSeconds, 5, maximumCompactLength, issuerAuthority);
    }

    public DpopProofVerifier(Clock clock, int maximumAgeSeconds, int maximumFutureSkewSeconds,
                             int maximumCompactLength, AuthorizationServerIssuerAuthority issuerAuthority) {
        this.clock = java.util.Objects.requireNonNull(clock);
        if (maximumAgeSeconds < 10 || maximumAgeSeconds > 120 || maximumFutureSkewSeconds < 0
                || maximumFutureSkewSeconds > 30 || maximumCompactLength < 512
                || maximumCompactLength > 16384) throw new IllegalArgumentException("DPoP verification bounds are invalid");
        this.maximumAgeSeconds = maximumAgeSeconds;
        this.maximumFutureSkewSeconds = maximumFutureSkewSeconds;
        this.maximumCompactLength = maximumCompactLength;
        try {
            this.tokenTarget = tokenTarget(java.util.Objects.requireNonNull(issuerAuthority).pinnedIssuer());
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("DPoP token target authority is invalid");
        }
    }

    public VerifiedDpopProof verifyTokenProof(String compact, String expectedMethod, String expectedTarget,
                                               String expectedNonce) {
        requireTokenTarget(expectedTarget);
        return verify(compact, expectedMethod, expectedTarget, expectedNonce, null, null, false);
    }

    public VerifiedDpopProof verifyNonceChallengeProof(String compact, String expectedMethod, String expectedTarget) {
        requireTokenTarget(expectedTarget);
        return verify(compact, expectedMethod, expectedTarget, null, null, null, true);
    }

    public VerifiedDpopProof verifyPresentedTokenProof(String compact, String expectedMethod, String expectedTarget) {
        try {
            requireTokenTarget(expectedTarget);
            if (compact == null || compact.length() > maximumCompactLength) throw rejected();
            var nonce = SignedJWT.parse(compact).getJWTClaimsSet().getStringClaim("nonce");
            return verifyTokenProof(compact, expectedMethod, expectedTarget, nonce);
        } catch (DpopProofRejectedException exception) {
            throw exception;
        } catch (Exception exception) {
            throw rejected();
        }
    }

    public VerifiedDpopProof verifyResourceProof(String compact, String expectedMethod, String expectedTarget,
                                                  String expectedNonce, String accessToken,
                                                  String expectedKeyThumbprint) {
        if (accessToken == null || accessToken.isBlank() || expectedKeyThumbprint == null) throw rejected();
        return verify(compact, expectedMethod, expectedTarget, expectedNonce, accessToken, expectedKeyThumbprint, false);
    }

    @Override public VerifiedDpopProof verifyResourceChallengeProof(String compact, String expectedMethod,
            String expectedTarget, String accessToken, String expectedKeyThumbprint) {
        if (accessToken == null || accessToken.isBlank() || expectedKeyThumbprint == null) throw rejected();
        return verify(compact, expectedMethod, expectedTarget, null, accessToken, expectedKeyThumbprint, true);
    }

    private VerifiedDpopProof verify(String compact, String expectedMethod, String expectedTarget,
                                     String expectedNonce, String accessToken, String expectedKeyThumbprint,
                                     boolean challenge) {
        try {
            if (compact == null || compact.length() > maximumCompactLength || !METHOD.matcher(expectedMethod).matches()
                    || (!challenge && !NONCE.matcher(expectedNonce).matches())) throw rejected();
            var normalizedTarget = normalizedTarget(expectedTarget);
            var segments = compact.split("\\.", -1);
            if (segments.length != 3) throw rejected();
            for (var segment : segments) requireCanonicalSegment(segment);
            @SuppressWarnings("unchecked")
            Map<String, Object> rawHeader = mapper.readValue(java.util.Base64.getUrlDecoder().decode(pad(segments[0])), Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> rawClaims = mapper.readValue(java.util.Base64.getUrlDecoder().decode(pad(segments[1])), Map.class);
            var expectedClaims = challenge ? accessToken == null ? CHALLENGE_CLAIMS
                    : Set.of("htm", "htu", "iat", "jti", "ath") : accessToken == null ? TOKEN_CLAIMS
                    : Set.of("htm", "htu", "iat", "jti", "nonce", "ath");
            if (!HEADER_KEYS.equals(rawHeader.keySet()) || !expectedClaims.equals(rawClaims.keySet())) throw rejected();
            var jwt = SignedJWT.parse(compact);
            var header = jwt.getHeader();
            if (!new JOSEObjectType("dpop+jwt").equals(header.getType())
                    || !JWSAlgorithm.ES256.equals(header.getAlgorithm()) || header.getKeyID() != null
                    || !(header.getJWK() instanceof ECKey key) || key.isPrivate() || !Curve.P_256.equals(key.getCurve())
                    || key.getKeyUse() != null || key.getAlgorithm() != null || key.getKeyID() != null
                    || !canonicalCoordinate(key.getX()) || !canonicalCoordinate(key.getY())
                    || !lowS(segments[2])
                    || !jwt.verify(new ECDSAVerifier(key))) throw rejected();
            var method = string(rawClaims.get("htm"));
            var target = normalizedTarget(string(rawClaims.get("htu")));
            var jti = string(rawClaims.get("jti"));
            var nonce = challenge ? null : string(rawClaims.get("nonce"));
            if (!expectedMethod.equals(method) || !normalizedTarget.equals(target) || !JTI.matcher(jti).matches()
                    || (!challenge && !expectedNonce.equals(nonce))) throw rejected();
            var iat = exactLong(rawClaims.get("iat"));
            var now = Instant.now(clock).getEpochSecond();
            if (iat > now + maximumFutureSkewSeconds || iat < now - maximumAgeSeconds) throw rejected();
            var thumbprint = key.computeThumbprint().toString();
            if (accessToken != null) {
                var expectedAth = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(accessToken.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                var suppliedAth = java.util.Base64.getUrlDecoder().decode(string(rawClaims.get("ath")) + "=");
                var expectedThumbprintBytes = expectedKeyThumbprint.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                var actualThumbprintBytes = thumbprint.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                if (!java.security.MessageDigest.isEqual(expectedAth, suppliedAth)
                        || !java.security.MessageDigest.isEqual(expectedThumbprintBytes, actualThumbprintBytes)) {
                    throw rejected();
                }
            }
            return new VerifiedDpopProof(method, target, Instant.ofEpochSecond(iat), jti, nonce, thumbprint);
        } catch (DpopProofRejectedException exception) {
            throw exception;
        } catch (Exception exception) {
            throw rejected();
        }
    }

    private static String normalizedTarget(String value) {
        var uri = URI.create(value);
        if (!uri.isAbsolute() || uri.getFragment() != null || uri.getUserInfo() != null || uri.getRawQuery() != null
                || !("https".equals(uri.getScheme())) || uri.getHost() == null || uri.getPort() == 443
                || !uri.getHost().equals(uri.getHost().toLowerCase(java.util.Locale.ROOT))
                || !canonicalPercentEncoding(uri.getRawPath())) throw rejected();
        var rawPath = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        if (!URI.create(rawPath).normalize().getRawPath().equals(rawPath)
                || java.util.Arrays.asList(rawPath.split("/", -1)).contains(".")) throw rejected();
        var result = URI.create("https://" + uri.getHost()
                + (uri.getPort() == -1 ? "" : ":" + uri.getPort()) + rawPath).toASCIIString();
        if (!result.equals(value)) throw rejected();
        return result;
    }

    private void requireTokenTarget(String expectedTarget) {
        if (!tokenTarget.equals(expectedTarget)) throw rejected();
    }

    private static String tokenTarget(String issuer) {
        var uri = URI.create(issuer);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getRawQuery() != null || uri.getFragment() != null || uri.getPort() == 443
                || !uri.getHost().equals(uri.getHost().toLowerCase(java.util.Locale.ROOT))
                || !(uri.getRawPath().isEmpty() || "/".equals(uri.getRawPath()))) {
            throw new IllegalArgumentException("issuer is invalid");
        }
        var origin = "https://" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        if (!(origin.equals(issuer) || (origin + "/").equals(issuer))) throw new IllegalArgumentException("issuer is invalid");
        return origin + "/oauth2/token";
    }

    private static boolean canonicalPercentEncoding(String rawPath) {
        for (int index = 0; index < rawPath.length(); index++) {
            if (rawPath.charAt(index) != '%') continue;
            if (index + 2 >= rawPath.length() || !uppercaseHex(rawPath.charAt(index + 1))
                    || !uppercaseHex(rawPath.charAt(index + 2))) return false;
            var decoded = Integer.parseInt(rawPath.substring(index + 1, index + 3), 16);
            if (decoded == '%' || isUnreserved(decoded)) return false;
            index += 2;
        }
        return true;
    }

    private static boolean uppercaseHex(char value) {
        return value >= '0' && value <= '9' || value >= 'A' && value <= 'F';
    }

    private static boolean isUnreserved(int value) {
        return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
                || value >= '0' && value <= '9' || value == '-' || value == '.' || value == '_' || value == '~';
    }

    private static void requireCanonicalSegment(String segment) {
        if (segment.isEmpty() || !segment.matches("^[A-Za-z0-9_-]+$")) throw rejected();
        var decoded = java.util.Base64.getUrlDecoder().decode(pad(segment));
        if (!segment.equals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded))) throw rejected();
    }

    private static boolean canonicalCoordinate(com.nimbusds.jose.util.Base64URL value) {
        if (value == null) return false;
        var text = value.toString();
        if (!text.matches("^[A-Za-z0-9_-]{43}$")) return false;
        try {
            var decoded = java.util.Base64.getUrlDecoder().decode(text);
            return decoded.length == 32
                    && text.equals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded));
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static boolean lowS(String encodedSignature) {
        var signature = java.util.Base64.getUrlDecoder().decode(pad(encodedSignature));
        if (signature.length != 64) return false;
        var order = new java.math.BigInteger(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        var s = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(signature, 32, 64));
        return s.signum() > 0 && s.compareTo(order.shiftRight(1)) <= 0;
    }

    private static String string(Object value) {
        if (!(value instanceof String text)) throw rejected();
        return text;
    }

    private static long exactLong(Object value) {
        if (value instanceof Integer integer) return integer.longValue();
        if (value instanceof Long longValue) return longValue;
        if (value instanceof java.math.BigInteger bigInteger) return bigInteger.longValueExact();
        throw rejected();
    }

    private static String pad(String segment) {
        var remainder = segment.length() % 4;
        return remainder == 0 ? segment : segment + "=".repeat(4 - remainder);
    }

    private static DpopProofRejectedException rejected() { return new DpopProofRejectedException(); }
}
