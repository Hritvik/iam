package dev.distracted.iam.registration;

import java.net.URI;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.networknt.schema.InputFormat;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import org.erdtman.jcs.JsonCanonicalizer;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

public final class StrictRegistrationManifestValidator implements RegistrationManifestValidator {
    private static final int MAX_BYTES = 32_768;
    private static final String SCHEMA_ID = "https://contracts.distracted.dev/iam/manifest/app-registration.schema.json";
    private final JsonMapper mapper = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();
    private final JsonSchema schema = schema();

    @Override
    public ValidatedRegistration validate(PinnedRegistrationDocument document) {
        if (document == null || document.bytes().length > MAX_BYTES) {
            throw new RegistrationException("registration_source_oversize");
        }
        try {
            var tree = mapper.readTree(document.bytes());
            if (!schema.validate(tree.toString(), InputFormat.JSON)
                    .isEmpty()) throw new RegistrationException("registration_schema_invalid");
            var manifest = mapper.treeToValue(tree, RegistrationManifest.class);
            validateShape(manifest);
            var canonical = new JsonCanonicalizer(document.bytes()).getEncodedUTF8();
            var digest = MessageDigest.getInstance("SHA-256").digest(canonical);
            return new ValidatedRegistration(manifest, HexFormat.of().formatHex(digest));
        } catch (RegistrationException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new RegistrationException("registration_json_invalid", exception);
        }
    }

    private static JsonSchema schema() {
        try {
            var root = StrictRegistrationManifestValidator.class
                    .getResource("/canonical-contracts/manifest/");
            if (root == null) throw new RegistrationException("registration_schema_missing");
            var config = SchemaValidatorsConfig.builder().formatAssertionsEnabled(true).build();
            var factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012,
                    builder -> builder.schemaMappers(mappers -> mappers.mapPrefix(
                            "https://contracts.distracted.dev/iam/manifest/", root.toString())));
            return factory.getSchema(SchemaLocation.of(SCHEMA_ID), config);
        } catch (RegistrationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new RegistrationException("registration_schema_invalid", exception);
        }
    }

    private static void validateShape(RegistrationManifest value) {
        if (value == null || !List.of(1, "dutch-development", "Dutch Development", "development")
                .equals(List.of(value.manifestVersion(), value.appRegistrationId(), value.displayName(), value.environment()))) {
            throw new RegistrationException("registration_manifest_invalid");
        }
        var client = value.client();
        var expectedClient = new RegistrationManifest.Client("dutch-mobile", "NATIVE_PUBLIC",
                List.of("dutch://oauth/callback"), List.of("authorization_code"), List.of("S256"), "EXTERNAL");
        if (!expectedClient.equals(client)) {
            throw new RegistrationException("registration_client_invalid");
        }
        client.redirectUris().forEach(uri -> validateRedirect(value.appRegistrationId(), uri));
        var resource = value.resource();
        if (!new RegistrationManifest.Resource("dutch-api", "https://api.dutch.invalid", List.of("member:read"))
                .equals(resource)) {
            throw new RegistrationException("registration_resource_invalid");
        }
        var policy = value.securityPolicy();
        if (!new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"),
                List.of("verified_identifier", "usable_factor", "recovery_path")).equals(policy)) {
            throw new RegistrationException("registration_policy_invalid");
        }
    }

    static void validateRedirect(String appId, String value) {
        validateRedirect(appId, value, Map.of());
    }

    static void validateRedirect(String appId, String value, Map<String, Set<String>> claimedHttpsDomains) {
        try {
            var uri = URI.create(value);
            if (uri.getUserInfo() != null || uri.getFragment() != null || value.contains("*")) failRedirect();
            var scheme = uri.getScheme();
            if ("dutch-development".equals(appId) && "dutch".equals(scheme)
                    && "oauth".equals(uri.getHost()) && "/callback".equals(uri.getRawPath())
                    && uri.getQuery() == null) return;
            if ("https".equals(scheme) && uri.getHost() != null && uri.getQuery() == null
                    && claimedHttpsDomains.getOrDefault(appId, Set.of()).contains(uri.getHost())) return;
            if ("http".equals(scheme) && validLoopback(uri)) return;
            throw new RegistrationException("registration_redirect_invalid");
        } catch (RegistrationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new RegistrationException("registration_redirect_invalid", exception);
        }
    }

    private static boolean validLoopback(URI uri) {
        if (uri.getPort() < 1 || uri.getPort() > 65_535 || uri.getQuery() != null) return false;
        var host = uri.getHost();
        if ("[::1]".equals(uri.getRawAuthority().split(":(?=\\d+$)")[0]) || "::1".equals(host)) return true;
        if (host == null) return false;
        var octets = host.split("\\.", -1);
        if (octets.length != 4) return false;
        try {
            if (Integer.parseInt(octets[0]) != 127) return false;
            for (var octet : octets) if (octet.isEmpty() || Integer.parseInt(octet) > 255) return false;
            return true;
        } catch (NumberFormatException exception) {
            return false;
        }
    }

    private static void failRedirect() { throw new RegistrationException("registration_redirect_invalid"); }
}
