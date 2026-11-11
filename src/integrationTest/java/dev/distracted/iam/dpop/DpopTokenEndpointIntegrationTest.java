package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.distracted.iam.authorization.AuthorizationCodeDigestCapability;
import dev.distracted.iam.authorization.HmacAuthorizationCodeDigestCapability;
import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.token.AccessTokenSigningCapability;
import dev.distracted.iam.token.AccessTokenSigningSnapshot;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** End-to-end W-7 slice: real Spring context, PostgreSQL, nonce challenge and signed DPoP token. */
@SpringBootTest(classes = {IamApplication.class, DpopTokenEndpointIntegrationTest.Support.class}, properties = {
        "iam.dpop.enabled=true",
        "iam.dpop.persistence.enabled=true",
        "iam.authorization.enabled=true",
        "iam.token.enabled=true",
        "iam.refresh.enabled=true",
        "iam.app-subject.enabled=true",
        "iam.registration.dutch-development.enabled=true",
        "iam.issuer=https://iam.distracted.invalid",
        "iam.environment=development",
        "iam.dpop.token-target=https://iam.distracted.invalid/oauth2/token",
        "spring.flyway.enabled=false",
        "spring.profiles.active=test"
})
@AutoConfigureMockMvc
class DpopTokenEndpointIntegrationTest {
    private static final String ISSUER = "https://iam.distracted.invalid";
    private static final String TARGET = ISSUER + "/oauth2/token";
    private static final String VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    private static final String CODE_ID = "acd_abcdefghijklmnopqrstuv12";
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String RECONCILER_PASSWORD = UUID.randomUUID().toString();
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
            statement.execute("create role unrelated_service nologin");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD + "' in role iam_runtime");
            statement.execute("create role iam_reconciler_login login password '" + RECONCILER_PASSWORD
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
        properties.add("spring.datasource.username", () -> "iam_runtime_login");
        properties.add("spring.datasource.password", () -> RUNTIME_PASSWORD);
        properties.add("iam.registration.reconciler.jdbc-url", POSTGRES::getJdbcUrl);
        properties.add("iam.registration.reconciler.username", () -> "iam_reconciler_login");
        properties.add("iam.registration.reconciler.password", () -> RECONCILER_PASSWORD);
    }

    @Autowired MockMvc mvc;
    @Autowired AuthorizationCodeDigestCapability codeDigests;

    private static JdbcTemplate owner() {
        return new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()));
    }

    @BeforeEach
    void seed() {
        var owner = owner();
        owner.execute("truncate token_issuance_audit_fact,dpop_replay,dpop_nonce,app_subject,authorization_audit_fact,"
                + "authorization_code,authorization_request,policy_activation_evidence,policy_grant_type,"
                + "product_security_policy,resource_scope,resource_registration,client_pkce_method,client_grant_type,"
                + "client_redirect_uri,client_registration,app_registration,human_identity cascade");
        owner.queryForObject("select reconcile_pinned_registration(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                "dutch-development", (short) 1, "Dutch Development", "development",
                "eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc",
                "dutch-mobile", "NATIVE_PUBLIC", "EXTERNAL", new String[] {"dutch://oauth/callback"},
                new String[] {"authorization_code"}, new String[] {"S256"}, "dutch-api",
                "https://api.dutch.invalid", new String[] {"member:read"}, true, "S256",
                new String[] {"verified_identifier", "usable_factor", "recovery_path"});
        owner.update("insert into human_identity(identity_id,state) values(?,?)", "hid_0123456789012345678901", "ACTIVE");
        owner.update("insert into app_subject(app_registration_id,human_identity_id,app_subject) values(?,?,?)",
                "dutch-development", "hid_0123456789012345678901", "aps_0123456789012345678901ab");
        var secret = new byte[32];
        java.util.Arrays.fill(secret, (byte) 7);
        var protection = codeDigests.protect(CODE_ID, secret);
        owner.queryForMap("select * from issue_authorization_code(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "arq_0123456789012345678901", CODE_ID, ISSUER, "dutch-development", "dutch-mobile", "dutch-api",
                "https://api.dutch.invalid", "hid_0123456789012345678901", "dutch://oauth/callback", "member:read",
                new byte[32], new byte[32], sha256(VERIFIER), protection.digest(), protection.keyVersion(), 120,
                "cor_0123456789012345");
        System.setProperty("iam.test.code", CODE_ID + "." + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(secret));
    }

    @Test
    void nonceChallengeThenRetryIssuesOneClosedDpopToken() throws Exception {
        var challenge = mvc.perform(tokenRequest(proof("challenge_jti_abcdefghijklmnop", null)))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.error").value("use_dpop_nonce"))
                .andExpect(jsonPath("$.error_description").value("A fresh DPoP nonce is required"))
                .andExpect(jsonPath("$.correlation_id").exists())
                .andReturn();
        var nonce = challenge.getResponse().getHeader("DPoP-Nonce");
        assertThat(nonce).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(owner().queryForObject("select count(*) from dpop_nonce where status='ISSUED'", Integer.class)).isEqualTo(1);

        mvc.perform(tokenRequest(proof("retry_jti_abcdefghijklmnopqrst", nonce)))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.token_type").value("DPoP"))
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(jsonPath("$.id_token").doesNotExist());
        assertThat(codeRow("token_issuance_audit_fact")).isEqualTo(1);

        // A consumed nonce yields a fresh challenge rather than a token.
        mvc.perform(tokenRequest(proof("third_jti_abcdefghijklmnopqrs", nonce)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("use_dpop_nonce"))
                .andExpect(header().exists("DPoP-Nonce"));
    }

    @Test
    void aConsumedCodeCannotBeReplayedWithAFreshNonce() throws Exception {
        var challenge = mvc.perform(tokenRequest(proof("retry1_jti_abcdefghijklmnopq", null))).andReturn();
        var nonce = challenge.getResponse().getHeader("DPoP-Nonce");
        mvc.perform(tokenRequest(proof("retry2_jti_abcdefghijklmnopq", nonce)))
                .andExpect(status().isOk());

        var second = mvc.perform(tokenRequest(proof("retry3_jti_abcdefghijklmnopq", null))).andReturn();
        var fresh = second.getResponse().getHeader("DPoP-Nonce");
        mvc.perform(tokenRequest(proof("retry4_jti_abcdefghijklmnopq", fresh)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void nonPostMethodsAndDuplicateProofHeadersAreRejected() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/oauth2/token"))
                .andExpect(status().isNotFound());
        mvc.perform(tokenRequest(proof("dup1_jti_abcdefghijklmnopqrs", null))
                        .header("DPoP", proof("dup2_jti_abcdefghijklmnopqrs", null)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_dpop_proof"));
    }

    @Test
    void refreshRotatesAndRejectsReuse() throws Exception {
        var challenge = mvc.perform(tokenRequest(proof("refreshchallenge_jti_abcdefghij", null))).andReturn();
        var nonce = challenge.getResponse().getHeader("DPoP-Nonce");
        var issued = mvc.perform(tokenRequest(proof("refreshissue_jti_abcdefghijklmno", nonce)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn();
        var mapper = new tools.jackson.databind.ObjectMapper();
        var refresh = mapper.readTree(issued.getResponse().getContentAsString())
                .required("refresh_token").textValue();

        var refreshChallenge = mvc.perform(refreshRequest(proof("refreshrotate1_jti_abcdefghij", null), refresh))
                .andReturn();
        var refreshNonce = refreshChallenge.getResponse().getHeader("DPoP-Nonce");
        var rotated = mvc.perform(refreshRequest(
                        proof("refreshrotate2_jti_abcdefghijklmn", refreshNonce), refresh))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(jsonPath("$.id_token").doesNotExist())
                .andReturn();
        assertThat(mapper.readTree(rotated.getResponse().getContentAsString())
                .required("refresh_token").textValue()).isNotEqualTo(refresh);

        var reuseChallenge = mvc.perform(refreshRequest(proof("refreshreuse1_jti_abcdefghij", null), refresh))
                .andReturn();
        var reuseNonce = reuseChallenge.getResponse().getHeader("DPoP-Nonce");
        mvc.perform(refreshRequest(proof("refreshreuse2_jti_abcdefghijklmn", reuseNonce), refresh))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        assertThat(owner().queryForObject("select status from refresh_family", String.class)).isEqualTo("REVOKED");
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder refreshRequest(
            String proof, String refresh) {
        return post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "refresh_token")
                .param("refresh_token", refresh)
                .param("client_id", "dutch-mobile")
                .header("DPoP", proof)
                .header("X-Correlation-ID", "cor_abcdefghijklmnop");
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder tokenRequest(String proof) {
        return post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", System.getProperty("iam.test.code"))
                .param("redirect_uri", "dutch://oauth/callback")
                .param("client_id", "dutch-mobile")
                .param("code_verifier", VERIFIER)
                .header("DPoP", proof)
                .header("X-Correlation-ID", "cor_abcdefghijklmnop");
    }

    private int codeRow(String table) {
        return owner().queryForObject("select count(*) from " + table, Integer.class);
    }

    private static byte[] sha256(String value) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String proof(String jti, String nonce) throws Exception {
        var builder = new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .issueTime(Date.from(Instant.now())).jwtID(jti);
        if (nonce != null) builder.claim("nonce", nonce);
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
                .jwk(Support.PROOF_KEY.toPublicJWK()).build(), builder.build());
        jwt.sign(new ECDSASigner(Support.PROOF_KEY));
        return withLowS(jwt.serialize());
    }

    private static String withLowS(String compact) {
        var parts = compact.split("\\.");
        var signature = java.util.Base64.getUrlDecoder().decode(parts[2]);
        var order = new java.math.BigInteger(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        var s = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(order.shiftRight(1)) > 0) {
            var source = order.subtract(s).toByteArray();
            var encoded = new byte[32];
            System.arraycopy(source, Math.max(0, source.length - 32), encoded,
                    Math.max(0, 32 - source.length), Math.min(32, source.length));
            System.arraycopy(encoded, 0, signature, 32, 32);
            parts[2] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        }
        return String.join(".", parts);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Support {
        static final ECKey KEY = generate("test-signing-key");
        static final ECKey PROOF_KEY = generate(null);

        @Bean DpopStateDigestCapability testDpopStateDigestCapability() {
            return new HmacDpopStateDigestCapability("test", (short) 1,
                    Map.of((short) 1, key((byte) 3)), Map.of((short) 1, "dpop-state-test-key"));
        }

        @Bean AuthorizationCodeDigestCapability testAuthorizationCodeDigestCapability() {
            return new HmacAuthorizationCodeDigestCapability("test", (short) 1,
                    Map.of((short) 1, key((byte) 5)), Map.of((short) 1, "code-digest-test-key"));
        }

        @Bean AccessTokenSigningCapability testAccessTokenSigningCapability() {
            return () -> new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", "test-signing-key",
                    List.of(KEY.toPublicJWK()), true, input -> {
                        try {
                            return new ECDSASigner(KEY).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode();
                        } catch (Exception exception) {
                            throw new IllegalStateException(exception);
                        }
                    });
        }

        private static byte[] key(byte seed) {
            var value = new byte[32];
            java.util.Arrays.fill(value, seed);
            return value;
        }

        private static ECKey generate(String keyId) {
            try {
                var generator = java.security.KeyPairGenerator.getInstance("EC");
                generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
                var pair = generator.generateKeyPair();
                var builder = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                        .privateKey((java.security.interfaces.ECPrivateKey) pair.getPrivate());
                if (keyId != null) {
                    builder.keyID(keyId).keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256);
                }
                return builder.build();
            } catch (Exception exception) {
                throw new IllegalStateException(exception);
            }
        }
    }
}
