package dev.distracted.iam.contracts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.networknt.schema.InputFormat;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

final class CanonicalContractsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());
    private static final Path CONTRACTS = Path.of(System.getProperty("contracts.dir"));
    private static final String BASE = "https://contracts.distracted.dev/iam/";
    private static final SchemaValidatorsConfig VALIDATION = SchemaValidatorsConfig.builder()
            .formatAssertionsEnabled(true).build();
    private static final JsonSchemaFactory SCHEMAS = JsonSchemaFactory.getInstance(
            SpecVersion.VersionFlag.V202012,
            builder -> builder.schemaMappers(mappers -> mappers.mapPrefix(BASE, CONTRACTS.toUri().toString())));
    private static final Set<String> FORBIDDEN_NAMES = Set.of(
            "identityid", "humanidentityid", "email", "phone", "credential", "authorizationcode",
            "accesstoken", "refreshtoken", "sessionsecret", "devicefingerprint", "crossappsubject");
    private static final Pattern EMAIL_VALUE = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern PHONE_VALUE = Pattern.compile("^\\+[1-9][0-9]{7,14}$");
    private static final Set<String> PUBLISHABLE_CONTRACT_PATHS = Set.of(
            "manifest/app-registration.schema.json",
            "manifest/dutch-development.app-registration.json",
            "manifest/product-security-policy.schema.json",
            "oauth/human-access-token-header.schema.json",
            "oauth/authorization-server-metadata.schema.json",
            "oauth/jwks.schema.json",
            "oauth/protected-resource-metadata.schema.json",
            "oauth/human-access-token-claims.schema.json",
            "oauth/dpop-proof-header.schema.json",
            "oauth/dpop-proof-claims.schema.json",
            "oauth/token-response.schema.json",
            "oauth/token-error-response.schema.json",
            "http/onboarding-snapshot-response.schema.json",
            "http/error-envelope.schema.json",
            "http/iam-onboarding-snapshot.openapi.yaml",
            "conformance/semantic-requirements.yaml",
            "events/event-envelope.schema.json",
            "events/iam.app-subject.onboarding-ready.v1.schema.json",
            "events/iam.app-subject.onboarding-ready.v1.payload.schema.json");

    @Test
    void catalogIsCompleteUniqueAndEveryEntryFullyParses() throws IOException {
        JsonNode catalog = catalog();
        assertEquals("1.0.0", catalog.required("version").textValue());
        Set<String> names = new HashSet<>();
        Set<String> paths = new HashSet<>();
        for (JsonNode contract : catalog.required("contracts")) {
            assertTrue(names.add(contract.required("name").textValue()), "duplicate contract name");
            String relativePath = contract.required("path").textValue();
            assertTrue(paths.add(relativePath), "duplicate contract path");
            assertEquals("1.0.0", contract.required("schemaVersion").textValue());
            Path path = CONTRACTS.resolve(relativePath);
            assertTrue(Files.isRegularFile(path), () -> "missing catalog entry " + path);
            String kind = contract.required("kind").textValue();
            if ("openapi".equals(kind)) {
                assertOpenApiParses(path);
            } else if ("json-schema".equals(kind)) {
                JsonNode schema = JSON.readTree(path.toFile());
                assertEquals(BASE + relativePath, schema.required("$id").textValue());
                SCHEMAS.getSchema(SchemaLocation.of(schema.required("$id").textValue()), VALIDATION);
            } else if ("example".equals(kind)) {
                assertTrue(validate(contract.required("schema").textValue(), JSON.readTree(path.toFile())).isEmpty());
            } else if ("requirements".equals(kind)) {
                JsonNode requirements = YAML.readTree(path.toFile());
                assertEquals("1.0.0", requirements.required("version").textValue());
                assertEquals("MUST", requirements.at("/event/onboardingCrossFieldEquality/level").textValue());
                assertEquals("MUST", requirements.at("/token/dutchRegistrationTuple/level").textValue());
                assertEquals("MUST", requirements.at("/token/dpopTokenEndpoint/level").textValue());
                assertEquals("MUST", requirements.at("/registration/redirectSafety/level").textValue());
                assertEquals("MUST", requirements.at("/snapshot/xExtensionsEnforcement/level").textValue());
            } else {
                throw new AssertionError("unknown catalog kind: " + kind);
            }
        }
        assertTrue(paths.contains("manifest/dutch-development.app-registration.json"));
        assertTrue(paths.contains("events/iam.app-subject.onboarding-ready.v1.payload.schema.json"));
        assertEquals(PUBLISHABLE_CONTRACT_PATHS, paths);
    }

    @Test
    void fixtureInventoryIsNonVacuousAndExternallyMapsSchemas() throws IOException {
        List<Path> valid = jsonFiles(CONTRACTS.resolve("fixtures/valid"));
        List<Path> invalid = jsonFiles(CONTRACTS.resolve("fixtures/invalid"));
        assertEquals(15, valid.size());
        assertEquals(58, invalid.size());
        for (Path fixture : valid) {
            JsonNode wrapper = JSON.readTree(fixture.toFile());
            List<String> failures = validateFixture(wrapper);
            assertTrue(failures.isEmpty(), () -> fixture + " must be valid: " + failures);
            assertFalse(containsProperty(wrapper.required("instance"), "$contract"), "$contract leaked onto wire");
        }
        for (Path fixture : invalid) {
            JsonNode wrapper = JSON.readTree(fixture.toFile());
            List<String> failures = validateFixture(wrapper);
            assertFalse(failures.isEmpty(), () -> fixture + " was unexpectedly accepted");
            String assertedReason = wrapper.required("assertedReason").textValue();
            assertTrue(failures.stream().anyMatch(failure -> failure.contains(assertedReason)),
                    () -> fixture + " failures did not contain '" + assertedReason + "': " + failures);
        }
    }

    @Test
    void validWireExamplesAndCanonicalExamplesContainNoForbiddenNamesOrValues() throws IOException {
        for (Path fixture : jsonFiles(CONTRACTS.resolve("fixtures/valid"))) {
            assertSafeTree(JSON.readTree(fixture.toFile()).required("instance"), fixture.toString());
        }
        assertSafeTree(JSON.readTree(CONTRACTS.resolve("manifest/dutch-development.app-registration.json").toFile()), "$manifest");
        for (Path schemaPath : catalogJsonSchemas()) {
            JsonNode schema = JSON.readTree(schemaPath.toFile());
            assertSchemaPropertyNames(schema, schemaPath.toString());
            assertSafeTree(schema, schemaPath.toString());
        }
        assertSafeTree(YAML.readTree(CONTRACTS.resolve("http/iam-onboarding-snapshot.openapi.yaml").toFile()), "$openapi");
    }

    @Test
    void onboardingEventUsesReusableEnvelopeAndEnforcesCrossFieldSemantics() throws IOException {
        JsonNode envelope = JSON.readTree(CONTRACTS.resolve("events/event-envelope.schema.json").toFile());
        assertEquals("^[a-z][a-z0-9.-]{2,127}$", envelope.at("/properties/eventType/pattern").textValue());
        JsonNode fixture = JSON.readTree(CONTRACTS.resolve("fixtures/valid/onboarding-ready-event.json").toFile());
        assertTrue(validateFixture(fixture).isEmpty());
        JsonNode event = fixture.required("instance");
        assertEquals("FIRST_ACTIVATION", event.at("/payload/onboardingReason").textValue());
        assertEquals(event.at("/destination/appRegistrationId"), event.at("/payload/appRegistrationId"));
        assertEquals(event.at("/aggregate/id"), event.at("/payload/activationId"));
        assertEquals(event.at("/aggregate/version"), event.at("/payload/onboardingVersion"));
    }

    @Test
    void snapshotPinsMtlsAppBindingAudienceScopeAndNonEnumeratingMismatch() throws IOException {
        Path specification = CONTRACTS.resolve("http/iam-onboarding-snapshot.openapi.yaml");
        OpenAPI openApi = parseOpenApi(specification);
        var scheme = openApi.getComponents().getSecuritySchemes().get("registeredWorkloadMtls");
        assertNotNull(scheme);
        assertEquals("mutualTLS", scheme.getType().toString());
        var operation = openApi.getPaths().get("/internal/v1/apps/{appRegistrationId}/onboarding").getGet();
        assertEquals(List.of(), operation.getSecurity().getFirst().get("registeredWorkloadMtls"));
        assertEquals("iam:onboarding:read", operation.getExtensions().get("x-required-scope"));
        assertEquals("https://iam.distracted.invalid/internal/onboarding",
                operation.getExtensions().get("x-required-audience"));
        assertEquals("path appRegistrationId MUST equal the authenticated workload app registration; mismatch returns 404",
                operation.getExtensions().get("x-workload-app-binding"));
        assertNotNull(operation.getResponses().get("404"));
        for (String status : List.of("429", "500", "503")) {
            assertNotNull(operation.getResponses().get(status), "missing response " + status);
        }
        assertEquals("#/components/responses/RetryableError", operation.getResponses().get("429").get$ref());
        assertEquals("#/components/responses/RetryableError", operation.getResponses().get("503").get$ref());
        assertNotNull(openApi.getComponents().getResponses().get("RetryableError").getHeaders().get("Retry-After"));
        assertEquals(200, operation.getParameters().stream().filter(p -> "limit".equals(p.getName()))
                .findFirst().orElseThrow().getSchema().getMaximum().intValue());
        JsonNode item = YAML.readTree(specification.toFile())
                .at("/components/schemas/OnboardingSnapshotEnvelope/properties/data/properties/items/items");
        assertFalse(item.required("additionalProperties").booleanValue());
        assertEquals(List.of("appSubject", "activationId", "activationState", "activationVersion",
                        "onboardingReason", "onboardingVersion", "requiredProfileState"),
                JSON.convertValue(item.required("required"), List.class));
        JsonNode details = YAML.readTree(specification.toFile())
                .at("/components/schemas/ErrorEnvelope/properties/error/properties/details/items");
        assertFalse(details.required("additionalProperties").booleanValue());
        Set<String> detailFields = new HashSet<>();
        details.path("properties").fieldNames().forEachRemaining(detailFields::add);
        assertEquals(Set.of("field", "code"), detailFields);
    }

    @Test
    void tokenFixtureSemanticallyConformsToDutchRegistration() throws IOException {
        JsonNode tokenFixture = JSON.readTree(CONTRACTS.resolve("fixtures/valid/token-claims.json").toFile());
        assertTrue(validateFixture(tokenFixture).isEmpty());
        JsonNode claims = tokenFixture.required("instance");
        assertEquals("https://iam.distracted.invalid", claims.required("iss").textValue());
        assertEquals("dutch-development", claims.required("app_id").textValue());
        assertEquals("dutch-mobile", claims.required("client_id").textValue());
        assertEquals("https://api.dutch.invalid", claims.required("aud").textValue());
        assertTrue(claims.has("cnf"));
        JsonNode manifest = JSON.readTree(CONTRACTS.resolve("manifest/dutch-development.app-registration.json").toFile());
        assertEquals(1, manifest.at("/client/redirectUris").size());
        assertEquals("dutch://oauth/callback", manifest.at("/client/redirectUris/0").textValue());
        assertEquals("authorization_code", manifest.at("/client/grantTypes/0").textValue());
    }

    @Test
    void rfc8252LoopbackSemanticValidationAcceptsOnlyValidIpAndExplicitPort() throws IOException {
        for (String redirect : List.of(
                "http://127.0.0.1:1/callback",
                "http://127.255.255.254:65535/callback",
                "http://[::1]:49152/callback")) {
            JsonNode manifest = JSON.readTree(CONTRACTS.resolve("manifest/dutch-development.app-registration.json").toFile());
            ((ArrayNode) manifest.at("/client/redirectUris")).removeAll().add(redirect);
            assertTrue(validateManifestSemantics(manifest).isEmpty(), () -> redirect + " must be accepted");
        }
    }

    @Test
    void catalogDoesNotPublishGlobalIdentityLifecycleOrClaimOidcDiscovery() throws IOException {
        String catalog = Files.readString(CONTRACTS.resolve("catalog.yaml"));
        assertFalse(catalog.contains("iam.identity.verified.v1"));
        assertFalse(catalog.toLowerCase(Locale.ROOT).contains("openid-configuration"));
    }

    private static List<String> validateFixture(JsonNode wrapper) throws IOException {
        String schema = wrapper.required("schema").textValue();
        JsonNode instance = wrapper.required("instance");
        List<String> failures = new ArrayList<>(validate(schema, instance));
        if (schema.endsWith("iam.app-subject.onboarding-ready.v1.schema.json")) {
            requireEqual(instance, "/destination/appRegistrationId", "/payload/appRegistrationId",
                    "destination.appRegistrationId", failures);
            requireEqual(instance, "/aggregate/id", "/payload/activationId", "aggregate.id", failures);
            requireEqual(instance, "/aggregate/version", "/payload/onboardingVersion", "aggregate.version", failures);
        }
        if (schema.endsWith("human-access-token-claims.schema.json")) {
            JsonNode manifest = JSON.readTree(CONTRACTS.resolve("manifest/dutch-development.app-registration.json").toFile());
            JsonNode metadata = validInstance("authorization-server-metadata.json");
            compare(instance, "iss", metadata, "issuer", "iss", failures);
            compare(instance, "app_id", manifest, "appRegistrationId", "app_id", failures);
            compare(instance, "client_id", manifest.path("client"), "clientId", "client_id", failures);
            compare(instance, "aud", manifest.path("resource"), "audience", "aud", failures);
            Set<String> allowed = new HashSet<>();
            manifest.at("/resource/allowedScopes").forEach(scope -> allowed.add(scope.textValue()));
            for (String scope : instance.path("scope").asText().split(" ")) {
                if (!allowed.contains(scope)) {
                    failures.add("scope must be a subset of Dutch allowedScopes");
                }
            }
            if (!instance.has("cnf")) {
                failures.add("cnf is required because Dutch requires DPoP");
            }
            if (instance.path("exp").canConvertToLong() && instance.path("iat").canConvertToLong()
                    && instance.path("exp").longValue() <= instance.path("iat").longValue()) {
                failures.add("exp must be greater than iat");
            }
            if (instance.has("auth_time") && instance.path("auth_time").longValue() > instance.path("iat").longValue()) {
                failures.add("auth_time must be less than or equal to iat");
            }
        }
        if (schema.endsWith("app-registration.schema.json")) {
            failures.addAll(validateManifestSemantics(instance));
        }
        return failures;
    }

    private static List<String> validateManifestSemantics(JsonNode manifest) {
        List<String> failures = new ArrayList<>();
        for (JsonNode redirectNode : manifest.at("/client/redirectUris")) {
            String value = redirectNode.textValue();
            try {
                URI redirect = new URI(value);
                if (redirect.getFragment() != null || redirect.getUserInfo() != null) {
                    failures.add("redirectUris must not contain userinfo or fragments");
                    continue;
                }
                int port = redirect.getPort();
                if (port == 0 || port > 65535) {
                    failures.add("redirectUris port must be between 1 and 65535");
                    continue;
                }
                String scheme = redirect.getScheme().toLowerCase(Locale.ROOT);
                if ("http".equals(scheme)) {
                    if (port < 1 || !isRfc8252LoopbackHost(redirect.getHost())) {
                        failures.add("redirectUris HTTP must use a valid RFC8252 loopback IP and explicit port");
                    }
                } else if ("https".equals(scheme)) {
                    if (redirect.getHost() == null) {
                        failures.add("redirectUris HTTPS must contain a valid claimed host");
                    }
                } else if (Set.of("javascript", "data", "file").contains(scheme)) {
                    failures.add("redirectUris contains a prohibited scheme");
                }
            } catch (IllegalArgumentException | URISyntaxException exception) {
                failures.add("redirectUris must contain a valid URI");
            }
        }
        return failures;
    }

    private static boolean isRfc8252LoopbackHost(String host) {
        if (host == null) {
            return false;
        }
        if ("::1".equals(host) || "[::1]".equals(host)) {
            return true;
        }
        String[] octets = host.split("\\.", -1);
        if (octets.length != 4 || !"127".equals(octets[0])) {
            return false;
        }
        for (String octet : octets) {
            if (!octet.matches("[0-9]{1,3}") || Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    private static Set<String> validate(String schemaId, JsonNode instance) {
        Set<String> failures = new HashSet<>();
        SCHEMAS.getSchema(SchemaLocation.of(schemaId), VALIDATION)
                .validate(instance.toString(), InputFormat.JSON)
                .forEach(message -> failures.add(message.getMessage()));
        return failures;
    }

    private static void requireEqual(JsonNode instance, String left, String right,
            String label, List<String> failures) {
        if (!instance.at(left).equals(instance.at(right))) {
            failures.add(label + " must match " + right);
        }
    }

    private static void compare(JsonNode left, String leftName, JsonNode right, String rightName,
            String label, List<String> failures) {
        if (!left.path(leftName).equals(right.path(rightName))) {
            failures.add(label + " must match Dutch registration");
        }
    }

    private static JsonNode validInstance(String fileName) throws IOException {
        return JSON.readTree(CONTRACTS.resolve("fixtures/valid").resolve(fileName).toFile()).required("instance");
    }

    private static boolean containsProperty(JsonNode node, String name) {
        if (node.isObject() && node.has(name)) {
            return true;
        }
        if (node.isContainerNode()) {
            for (JsonNode child : node) {
                if (containsProperty(child, name)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void assertSafeTree(JsonNode node, String path) {
        if (node.isObject()) {
            node.properties().forEach(entry -> {
                boolean sanctionedTokenCredential = (path.contains("token-response.json")
                        || path.contains("oauth/token-response.schema.json"))
                        && "access_token".equals(entry.getKey());
                assertTrue(sanctionedTokenCredential || !FORBIDDEN_NAMES.contains(normalizeName(entry.getKey())),
                        path + " contains " + entry.getKey());
                assertSafeTree(entry.getValue(), path + "/" + entry.getKey());
            });
        } else if (node.isArray()) {
            node.forEach(child -> assertSafeTree(child, path + "[]"));
        } else if (node.isTextual()) {
            assertFalse(EMAIL_VALUE.matcher(node.textValue()).matches(), path + " contains raw email");
            assertFalse(PHONE_VALUE.matcher(node.textValue()).matches(), path + " contains raw phone");
        }
    }

    private static void assertSchemaPropertyNames(JsonNode node, String path) {
        if (node.isObject()) {
            JsonNode properties = node.path("properties");
            if (properties.isObject()) {
                properties.fieldNames().forEachRemaining(name -> {
                    boolean sanctionedTokenCredential = path.contains("oauth/token-response.schema.json")
                            && "access_token".equals(name);
                    assertTrue(sanctionedTokenCredential || !FORBIDDEN_NAMES.contains(normalizeName(name)),
                            path + " publishes " + name);
                });
            }
            node.properties().forEach(entry -> assertSchemaPropertyNames(entry.getValue(), path + "/" + entry.getKey()));
        } else if (node.isArray()) {
            node.forEach(child -> assertSchemaPropertyNames(child, path + "[]"));
        }
    }

    private static String normalizeName(String value) {
        return value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    }

    private static JsonNode catalog() throws IOException {
        return YAML.readTree(CONTRACTS.resolve("catalog.yaml").toFile());
    }

    private static List<Path> catalogJsonSchemas() throws IOException {
        List<Path> paths = new ArrayList<>();
        for (JsonNode entry : catalog().required("contracts")) {
            if ("json-schema".equals(entry.required("kind").textValue())) {
                paths.add(CONTRACTS.resolve(entry.required("path").textValue()));
            }
        }
        return paths;
    }

    private static void assertOpenApiParses(Path path) {
        parseOpenApi(path);
    }

    private static OpenAPI parseOpenApi(Path path) {
        SwaggerParseResult result = new OpenAPIV3Parser().readLocation(path.toString(), null, null);
        assertTrue(result.getMessages().isEmpty(), () -> "OpenAPI parse errors: " + result.getMessages());
        assertNotNull(result.getOpenAPI());
        return result.getOpenAPI();
    }

    private static List<Path> jsonFiles(Path directory) throws IOException {
        try (Stream<Path> paths = Files.list(directory)) {
            return paths.filter(path -> path.getFileName().toString().endsWith(".json")).sorted().toList();
        }
    }
}
