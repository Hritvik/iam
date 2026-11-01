package dev.distracted.iam.token;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import dev.distracted.iam.registration.RegistrationRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import tools.jackson.databind.ObjectMapper;

public final class HumanAccessTokenIssuer {
    private static final Pattern JTI = Pattern.compile("^[A-Za-z0-9_-]{22,128}$");
    private static final Pattern SCOPE = Pattern.compile("^[a-z][a-z0-9:_-]{0,63}$");
    private final RegistrationRegistry registrations;
    private final AppSubjectBindingVerifier bindings;
    private final AccessTokenSigningSnapshot signer;
    private final AccessTokenMaterialGenerator material;
    private final Clock clock;
    private final String issuer;
    private final Duration lifetime;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HumanAccessTokenIssuer(RegistrationRegistry registrations, AppSubjectBindingVerifier bindings,
                                  AccessTokenSigningCapability signer, AccessTokenMaterialGenerator material,
                                  Clock clock, String configuredIssuer,
                                  AuthorizationServerIssuerAuthority issuerAuthority,
                                  Duration lifetime) {
        this.registrations = Objects.requireNonNull(registrations);
        this.bindings = Objects.requireNonNull(bindings);
        this.signer = JwksPublisher.capture(signer);
        this.material = Objects.requireNonNull(material);
        this.clock = Objects.requireNonNull(clock);
        var pinnedIssuer = requireIssuer(readIssuer(issuerAuthority));
        if (!pinnedIssuer.equals(requireIssuer(configuredIssuer))) throw rejected("invalid_context");
        this.issuer = pinnedIssuer;
        this.lifetime = requireLifetime(lifetime);
        verifyCapability(this.signer);
    }

    public SignedHumanAccessToken issue(HumanAccessTokenIssueCommand command) {
        try {
            return issueSafely(command);
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw rejected("invalid_context");
        }
    }

    private SignedHumanAccessToken issueSafely(HumanAccessTokenIssueCommand command) {
        Objects.requireNonNull(command, "command is required");
        var authorization = command.authorization();
        // A composed token-endpoint caller resolves the pinned manifest on the request thread and carries it in the
        // command, so the bounded signing worker never touches the database. The registry fallback exists only for
        // direct library callers and tests.
        var registration = command.registration() != null ? command.registration()
                : registrations.findByAppId(authorization.appRegistrationId())
                        .orElseThrow(() -> rejected("invalid_context"));
        var canonicalScope = canonicalScope(authorization.scope());
        if (!registration.appRegistrationId().equals(authorization.appRegistrationId())
                || !registration.client().clientId().equals(authorization.clientId())
                || !registration.resource().resourceId().equals(authorization.resourceId())
                || !registration.resource().audience().equals(authorization.resourceAudience())
                || !registration.securityPolicy().requireDpop()
                || !registration.resource().allowedScopes().containsAll(List.of(canonicalScope.split(" ")))
                || (command.registration() == null
                        && !bindings.belongsTo(authorization.humanIdentityId(), authorization.appRegistrationId(),
                                command.appSubject()))) {
            throw rejected("invalid_context");
        }
        var now = Instant.now(clock).getEpochSecond();
        final long expiry;
        try {
            expiry = Math.addExact(now, lifetime.toSeconds());
        } catch (ArithmeticException | DateTimeException exception) {
            throw rejected("invalid_context");
        }
        if (now <= 0 || expiry <= now) throw rejected("invalid_context");
        var jti = material.nextJti();
        if (jti == null || !JTI.matcher(jti).matches()) throw rejected("invalid_context");

        var header = new LinkedHashMap<String, Object>();
        header.put("typ", "at+jwt");
        header.put("alg", "ES256");
        header.put("kid", signer.activeKeyId());
        var claims = new LinkedHashMap<String, Object>();
        claims.put("iss", issuer);
        claims.put("sub", command.appSubject().value());
        claims.put("aud", authorization.resourceAudience());
        claims.put("iat", now);
        claims.put("exp", expiry);
        claims.put("jti", jti);
        claims.put("client_id", authorization.clientId());
        claims.put("token_profile", "human_access");
        claims.put("token_version", 1);
        claims.put("subject_kind", "app_subject");
        claims.put("scope", canonicalScope);
        claims.put("app_id", authorization.appRegistrationId());
        claims.put("security_version", command.securityVersion());
        claims.put("cnf", Map.of("jkt", command.dpopKeyThumbprint().value()));
        try {
            var encodedHeader = Base64URL.encode(objectMapper.writeValueAsBytes(header));
            var encodedClaims = Base64URL.encode(objectMapper.writeValueAsBytes(claims));
            var signingInput = (encodedHeader + "." + encodedClaims).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            var signature = signer.sign(signingInput);
            if (signature == null || signature.length != 64) throw rejected("signing_failed");
            var compact = encodedHeader + "." + encodedClaims + "." + Base64URL.encode(signature);
            verifyProduced(compact);
            return new SignedHumanAccessToken(compact);
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw rejected("signing_failed");
        }
    }

    private static String readIssuer(AuthorizationServerIssuerAuthority authority) {
        try {
            return Objects.requireNonNull(authority, "issuer authority is required").pinnedIssuer();
        } catch (RuntimeException exception) {
            throw rejected("invalid_context");
        }
    }

    private void verifyProduced(String compact) {
        try {
            var active = signer.publicJwks().stream()
                    .filter(key -> signer.activeKeyId().equals(key.getKeyID()))
                    .findFirst().orElseThrow();
            var object = com.nimbusds.jose.JWSObject.parse(compact);
            if (!object.verify(new ECDSAVerifier(active))) throw rejected("signing_failed");
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (Exception exception) {
            throw rejected("signing_failed");
        }
    }

    private static void verifyCapability(AccessTokenSigningSnapshot snapshot) {
        new JwksPublisher(snapshot);
    }

    private static String canonicalScope(String raw) {
        if (raw == null || raw.isBlank()) throw rejected("invalid_context");
        var values = Arrays.asList(raw.split(" ", -1));
        if (values.size() > 32 || values.stream().anyMatch(value -> !SCOPE.matcher(value).matches())
                || Set.copyOf(values).size() != values.size()) {
            throw rejected("invalid_context");
        }
        var sorted = values.stream().sorted().toList();
        if (!values.equals(sorted)) throw rejected("invalid_context");
        return String.join(" ", sorted);
    }

    private static String requireIssuer(String value) {
        if (value == null || !value.startsWith("https://") || value.length() > 256) {
            throw new IllegalArgumentException("issuer is invalid");
        }
        return value;
    }

    private static Duration requireLifetime(Duration value) {
        if (value == null || value.compareTo(Duration.ofSeconds(60)) < 0
                || value.compareTo(Duration.ofSeconds(900)) > 0 || value.getNano() != 0) {
            throw new IllegalArgumentException("token lifetime is invalid");
        }
        return value;
    }

    private static HumanAccessTokenIssueException rejected(String reason) {
        return new HumanAccessTokenIssueException(reason);
    }
}
