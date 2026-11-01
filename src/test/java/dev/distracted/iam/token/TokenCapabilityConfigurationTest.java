package dev.distracted.iam.token;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.token.web.JwksController;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class TokenCapabilityConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TokenCapabilityConfiguration.class);

    @Test void disabledHasNoJwksAndEnabledWithoutExternalSignerFailsClosed() {
        runner.run(context -> assertThat(context).doesNotHaveBean(JwksPublisher.class));
        runner.withPropertyValues("iam.token.enabled=true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasMessageContaining("AccessTokenSigningCapability");
        });
    }

    @Test void explicitHealthyExternalSignerEnablesPublicMaterial() throws Exception {
        var key = key();
        runner.withPropertyValues("iam.token.enabled=true")
                .withBean(AccessTokenSigningCapability.class, () -> new Signer(key))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JwksPublisher.class);
                    assertThat(context.getBean(JwksPublisher.class).document().keys()).hasSize(1);
                });
    }

    @Test void realWebContextPublishesJwksOnlyWhenExplicitlyEnabledWithSigner() throws Exception {
        var key = key();
        var web = new WebApplicationContextRunner().withUserConfiguration(IamApplication.class)
                .withPropertyValues("iam.token.enabled=true", "iam.token.issuer-authority.enabled=false",
                        "spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration")
                .withBean(AccessTokenSigningCapability.class, () -> new Signer(key),
                        definition -> definition.setPrimary(true));
        web.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JwksPublisher.class);
            assertThat(context).hasSingleBean(JwksController.class);
            assertThat(context).hasBean("jwksSecurityFilterChain");
            assertThat(context).doesNotHaveBean("authorizationServerSecurityFilterChain");
        });
    }

    @Test void fullWebContextRestartPublishesExternallyRotatedOverlapDeterministically() throws Exception {
        var oldKey = key("external01");
        var newKey = key("external02");
        var firstEtag = new java.util.concurrent.atomic.AtomicReference<String>();
        webRunner(new Signer(oldKey)).run(context -> {
            assertThat(context).hasNotFailed();
            firstEtag.set(context.getBean(JwksPublisher.class).etag());
            assertThat(context.getBean(JwksPublisher.class).document().keys())
                    .extracting(value -> value.get("kid")).containsExactly("external01");
        });
        webRunner(new Signer(newKey, List.of(oldKey.toPublicJWK(), newKey.toPublicJWK()))).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(JwksPublisher.class).etag()).isNotEqualTo(firstEtag.get());
            assertThat(context.getBean(JwksPublisher.class).document().keys())
                    .extracting(value -> value.get("kid")).containsExactly("external01", "external02");
        });
    }

    private static WebApplicationContextRunner webRunner(AccessTokenSigningCapability capability) {
        return new WebApplicationContextRunner().withUserConfiguration(IamApplication.class)
                .withPropertyValues("iam.token.enabled=true", "iam.token.issuer-authority.enabled=false",
                        "spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration")
                .withBean(AccessTokenSigningCapability.class, () -> capability,
                        definition -> definition.setPrimary(true));
    }

    private static ECKey key() throws Exception {
        return key("external01");
    }

    private static ECKey key(String keyId) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(keyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
    }

    private record Signer(ECKey key, List<ECKey> publicKeys) implements AccessTokenSigningCapability {
        private Signer(ECKey key) { this(key, List.of(key.toPublicJWK())); }
        @Override public AccessTokenSigningSnapshot snapshot() {
            return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(), publicKeys,
                    true, this::sign);
        }
        private byte[] sign(byte[] input) {
            try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
            catch (Exception exception) { throw new IllegalStateException(exception); }
        }
    }
}
