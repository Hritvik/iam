package dev.distracted.iam.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.platform.http.CorrelationIdFilter;
import dev.distracted.iam.registration.adapter.jdbc.JdbcRegistrationRegistry;
import dev.distracted.iam.registration.web.RegistrationMetadataController;
import com.networknt.schema.InputFormat;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import java.sql.DriverManager;
import java.nio.file.Path;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest(classes = IamApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RegistrationMetadataHttpIntegrationTest {
    private static final String RUNTIME_PASSWORD = "runtime-http-placeholder";
    private static final String RECONCILER_PASSWORD = "reconciler-http-placeholder";
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");

    static {
        POSTGRES.start();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role iam_runtime_http login password '" + RUNTIME_PASSWORD + "' in role iam_runtime");
            statement.execute("create role iam_reconciler_http login password '" + RECONCILER_PASSWORD
                    + "' in role iam_registration_reconciler");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", () -> "iam_runtime_http");
        properties.add("spring.datasource.password", () -> RUNTIME_PASSWORD);
        properties.add("spring.flyway.enabled", () -> "false");
        properties.add("spring.profiles.active", () -> "test");
        properties.add("iam.registration.dutch-development.enabled", () -> "true");
        properties.add("iam.environment", () -> "development");
        properties.add("iam.issuer", () -> "https://iam.distracted.invalid");
        properties.add("iam.registration.reconciler.jdbc-url", POSTGRES::getJdbcUrl);
        properties.add("iam.registration.reconciler.username", () -> "iam_reconciler_http");
        properties.add("iam.registration.reconciler.password", () -> RECONCILER_PASSWORD);
    }

    @org.springframework.beans.factory.annotation.Autowired MockMvc mvc;

    @BeforeEach
    void restoreCanonicalGraph() {
        var owner = owner();
        owner.execute("truncate app_activation,token_issuance_audit_fact,dpop_replay,dpop_nonce,app_subject,authorization_audit_fact,authorization_code,authorization_request,policy_activation_evidence,policy_grant_type,product_security_policy,resource_scope,"
                + "resource_registration,client_pkce_method,client_grant_type,client_redirect_uri,client_registration,"
                + "app_registration cascade");
        new JdbcRegistrationRegistry(reconcilerJdbc()).reconcile(new StrictRegistrationManifestValidator()
                .validate(new ClasspathPinnedRegistrationSource().load()));
    }

    @Test
    void persistedMetadataGetAndHeadAreExactSafeAndCorrelated() throws Exception {
        var authorization = mvc.perform(get("/.well-known/oauth-authorization-server")
                        .header("X-Correlation-Id", "real-db-correlation"))
                .andExpect(status().isOk()).andExpect(content().contentType("application/json"))
                .andExpect(header().string("Cache-Control", "max-age=300, public"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Correlation-Id", "real-db-correlation"))
                .andExpect(jsonPath("$.issuer").value("https://iam.distracted.invalid"))
                .andExpect(jsonPath("$.grant_types_supported[0]").value("authorization_code"))
                .andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256")).andReturn();
        assertSchema("oauth/authorization-server-metadata.schema.json",
                "https://contracts.distracted.dev/iam/oauth/authorization-server-metadata.schema.json",
                authorization.getResponse().getContentAsString());
        var resource = mvc.perform(get("/.well-known/oauth-protected-resource?app=rogue&resource=rogue")
                        .header("X-Correlation-Id", "resource-get-correlation"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.resource").value("https://api.dutch.invalid"))
                .andExpect(header().string("X-Correlation-Id", "resource-get-correlation"))
                .andExpect(jsonPath("$.scopes_supported[0]").value("member:read")).andReturn();
        assertSchema("oauth/protected-resource-metadata.schema.json",
                "https://contracts.distracted.dev/iam/oauth/protected-resource-metadata.schema.json",
                resource.getResponse().getContentAsString());
        mvc.perform(head("/.well-known/oauth-authorization-server")
                        .header("X-Correlation-Id", "authorization-head-correlation")).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", authorization.getResponse().getHeader("Cache-Control")))
                .andExpect(header().string("Content-Type", authorization.getResponse().getHeader("Content-Type")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Correlation-Id", "authorization-head-correlation"))
                .andExpect(content().string(""));
        mvc.perform(head("/.well-known/oauth-protected-resource")
                        .header("X-Correlation-Id", "resource-head-correlation")).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", resource.getResponse().getHeader("Cache-Control")))
                .andExpect(header().string("Content-Type", resource.getResponse().getHeader("Content-Type")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Correlation-Id", "resource-head-correlation"))
                .andExpect(content().string(""));
    }

    @Test
    void unsafeMethodsAndNearMissesRemainClosed() throws Exception {
        for (var request : new org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder[]{
                post("/.well-known/oauth-authorization-server"), put("/.well-known/oauth-authorization-server"),
                patch("/.well-known/oauth-protected-resource"), delete("/.well-known/oauth-protected-resource"),
                get("/.well-known/oauth-authorization-server/extra"), get("/.well-known/%6fauth-protected-resource")}) {
            mvc.perform(request).andExpect(status().is4xxClientError());
        }
    }

    @Test
    void absentOrAmbiguousRegistryReturnsSafeRetryableError() throws Exception {
        owner().execute("truncate app_activation,token_issuance_audit_fact,dpop_replay,dpop_nonce,app_subject,authorization_audit_fact,authorization_code,authorization_request,policy_activation_evidence,policy_grant_type,product_security_policy,resource_scope,"
                + "resource_registration,client_pkce_method,client_grant_type,client_redirect_uri,client_registration,"
                + "app_registration cascade");
        mvc.perform(get("/.well-known/oauth-protected-resource").header("X-Correlation-Id", "missing-db"))
                .andExpect(status().isServiceUnavailable()).andExpect(header().string("Retry-After", "30"))
                .andExpect(jsonPath("$.error.code").value("metadata_unavailable"))
                .andExpect(jsonPath("$.error.correlationId").value("missing-db"))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("SQL"))));
        owner().update("insert into app_registration(app_registration_id,manifest_version,display_name,environment,"
                        + "source_fingerprint) values (?,?,?,?,?)", "other-development", 1, "Other", "development",
                "b".repeat(64));
        mvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isServiceUnavailable()).andExpect(header().string("Retry-After", "30"));
    }

    @ParameterizedTest
    @MethodSource("metadataDriftMutations")
    void everyPersistedDriftShapeFailsClosedOnBothMetadataEndpoints(String mutation) throws Exception {
        owner().execute(mutation);
        for (var path : new String[]{"/.well-known/oauth-authorization-server",
                "/.well-known/oauth-protected-resource"}) {
            mvc.perform(get(path).header("X-Correlation-Id", "drift-canary"))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(header().string("Retry-After", "30"))
                    .andExpect(jsonPath("$.error.code").value("metadata_unavailable"))
                    .andExpect(jsonPath("$.error.correlationId").value("drift-canary"))
                    .andExpect(content().string(org.hamcrest.Matchers.not(
                            org.hamcrest.Matchers.containsString("Changed"))));
        }
    }

    static java.util.stream.Stream<String> metadataDriftMutations() {
        return java.util.stream.Stream.concat(RegistrationPersistenceIntegrationTest.persistedDriftMutations(),
                java.util.stream.Stream.of(
                        "insert into client_redirect_uri values ('dutch-mobile','dutch://other/callback')",
                        "insert into resource_scope values ('dutch-api','member:write')"));
    }

    @Test
    void actualDatabaseOutageReturnsOnlySafeRetryableHttpError() throws Exception {
        String url;
        try (var unavailable = new PostgreSQLContainer("postgres:18-alpine")) {
            unavailable.start();
            url = unavailable.getJdbcUrl();
        }
        var registry = new JdbcRegistrationRegistry(new JdbcTemplate(new DriverManagerDataSource(
                url, "outage-placeholder", "outage-placeholder")));
        var endpoint = MockMvcBuilders.standaloneSetup(new RegistrationMetadataController(
                        new RegistryRegistrationMetadata(registry, "https://iam.distracted.invalid")))
                .setControllerAdvice(new RegistrationMetadataExceptionHandler())
                .addFilter(new CorrelationIdFilter()).build();
        endpoint.perform(get("/.well-known/oauth-protected-resource").header("X-Correlation-Id", "outage-canary"))
                .andExpect(status().isServiceUnavailable()).andExpect(header().string("Retry-After", "30"))
                .andExpect(jsonPath("$.error.code").value("metadata_unavailable"))
                .andExpect(jsonPath("$.error.correlationId").value("outage-canary"))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("jdbc"))));
    }

    @Test
    void completeApplicationRestartReadsTheSameCanonicalRegistrationAndMetadata() {
        AuthorizationServerMetadata firstAuthorization;
        ProtectedResourceMetadata firstResource;
        try (var first = applicationContext()) {
            firstAuthorization = first.getBean(RegistrationMetadata.class).authorizationServer();
            firstResource = first.getBean(RegistrationMetadata.class).protectedResource();
        }
        try (var restarted = applicationContext()) {
            assertThat(restarted.getBean(RegistrationMetadata.class).authorizationServer()).isEqualTo(firstAuthorization);
            assertThat(restarted.getBean(RegistrationMetadata.class).protectedResource()).isEqualTo(firstResource);
            assertThat(restarted.getBean("registrationRegistry", RegistrationRegistry.class).findSoleRegistration())
                    .isPresent();
        }
    }

    private static org.springframework.context.ConfigurableApplicationContext applicationContext() {
        return new SpringApplicationBuilder(IamApplication.class).profiles("test").properties(
                "server.port=0", "spring.flyway.enabled=false", "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=iam_runtime_http", "spring.datasource.password=" + RUNTIME_PASSWORD,
                "iam.registration.dutch-development.enabled=true", "iam.environment=development",
                "iam.issuer=https://iam.distracted.invalid",
                "iam.registration.reconciler.jdbc-url=" + POSTGRES.getJdbcUrl(),
                "iam.registration.reconciler.username=iam_reconciler_http",
                "iam.registration.reconciler.password=" + RECONCILER_PASSWORD).run();
    }

    private static void assertSchema(String relativePath, String schemaId, String json) {
        var root = Path.of("contracts").toUri().toString();
        var factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012,
                builder -> builder.schemaMappers(mappers -> mappers.mapPrefix(
                        "https://contracts.distracted.dev/iam/", root)));
        var schema = factory.getSchema(SchemaLocation.of(schemaId),
                SchemaValidatorsConfig.builder().formatAssertionsEnabled(true).build());
        org.assertj.core.api.Assertions.assertThat(schema.validate(json, InputFormat.JSON)).isEmpty();
    }

    private static JdbcTemplate owner() {
        return new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    private static JdbcTemplate reconcilerJdbc() {
        return new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), "iam_reconciler_http", RECONCILER_PASSWORD));
    }
}
