package dev.distracted.iam.dpop;

import dev.distracted.iam.activation.AppSubjectResolver;
import dev.distracted.iam.activation.AppSubjectResolutionCommand;
import dev.distracted.iam.authorization.AuthorizationCodeRedemption;
import dev.distracted.iam.authorization.refresh.RefreshTokenMaterialGenerator;
import dev.distracted.iam.authorization.refresh.RefreshTokenRepository;
import dev.distracted.iam.dpop.adapter.jdbc.JdbcDpopStateStore;
import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.messaging.CorrelationId;
import dev.distracted.iam.platform.persistence.SpringTransactionRunner;
import dev.distracted.iam.registration.RegistrationRegistry;
import dev.distracted.iam.token.AccessTokenSigningCapability;
import dev.distracted.iam.token.AuthorizationServerIssuerAuthority;
import dev.distracted.iam.token.HumanAccessTokenIssueCommand;
import dev.distracted.iam.token.HumanAccessTokenIssuer;
import dev.distracted.iam.token.HumanAccessTokenVerifier;
import dev.distracted.iam.token.SecureAccessTokenMaterialGenerator;
import java.time.Clock;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.dpop.enabled", havingValue = "true")
@ConditionalOnProperty(name = "iam.dpop.persistence.enabled", havingValue = "true", matchIfMissing = true)
public class DpopApplicationConfiguration {
    @Bean DpopStateStore dpopStateStore(JdbcTemplate jdbc) { return new JdbcDpopStateStore(jdbc); }
    @Bean DpopProofValidation dpopProofValidation(
            @Value("${iam.dpop.proof-maximum-age-seconds:60}") int age,
            @Value("${iam.dpop.proof-maximum-future-skew-seconds:5}") int skew,
            @Value("${iam.dpop.proof-maximum-characters:16384}") int length,
            AuthorizationServerIssuerAuthority issuerAuthority) {
        return new DpopProofVerifier(Clock.systemUTC(), age, skew, length, issuerAuthority);
    }
    @Bean SecureDpopNonceGenerator secureDpopNonceGenerator() { return new SecureDpopNonceGenerator(); }

    @Bean DpopProtectedRequestVerifier dpopProtectedRequestVerifier(DpopProofValidation proofs,
            DpopStateDigestCapability digests, DpopStateStore state, AccessTokenSigningCapability signer,
            AuthorizationServerIssuerAuthority issuerAuthority,
            @Value("${iam.dpop.replay-retention:180s}") Duration retention,
            @Value("${iam.dpop.proof-maximum-age-seconds:60}") int proofMaximumAgeSeconds,
            @Value("${iam.dpop.proof-maximum-future-skew-seconds:5}") int proofMaximumFutureSkewSeconds,
            @Value("${iam.token.verification-skew:30s}") Duration skew) {
        var snapshot = signer.snapshot();
        var verifier = new HumanAccessTokenVerifier(snapshot.publicJwks(), Clock.systemUTC(),
                issuerAuthority.pinnedIssuer(), skew);
        return new DpopProtectedRequestVerifier(verifier::verify, proofs, digests, state,
                replayRetentionSeconds(retention, proofMaximumAgeSeconds, proofMaximumFutureSkewSeconds));
    }

    @Bean
    HumanAccessTokenIssuer humanAccessTokenIssuer(@Qualifier("registrationRegistry") RegistrationRegistry registrations,
            AccessTokenSigningCapability signer, AuthorizationServerIssuerAuthority issuerAuthority,
            @Value("${iam.issuer}") String issuer, @Value("${iam.token.lifetime:300s}") Duration lifetime) {
        // The orchestrator reads and locks the active identity/security context on the request thread inside the
        // issuance transaction and always supplies the manifest. The issuer's registry fallback and binding hook are
        // therefore unreachable here; fail closed rather than silently allowing if that ever changes.
        return new HumanAccessTokenIssuer(registrations, (identity, app, subject) -> {
            throw new IllegalStateException("binding verifier is unavailable for composed issuance");
        }, signer, new SecureAccessTokenMaterialGenerator(new java.security.SecureRandom()),
                Clock.systemUTC(), issuer, issuerAuthority, lifetime);
    }

    @Bean(destroyMethod = "close") DeadlineTokenAccessIssuer deadlineTokenAccessIssuer(HumanAccessTokenIssuer issuer,
            @Value("${iam.dpop.signer-timeout:2s}") Duration timeout,
            @Value("${iam.dpop.signer-workers:2}") int workers,
            @Value("${iam.dpop.signer-queue-capacity:16}") int queueCapacity) {
        TokenAccessIssuer delegate = (authorization, subject, securityVersion, thumbprint, correlation, registration) ->
                issuer.issue(new HumanAccessTokenIssueCommand(authorization, registration, subject, securityVersion,
                        thumbprint, correlation)).compactValue();
        return new DeadlineTokenAccessIssuer(delegate, timeout, workers, queueCapacity);
    }

    @Bean @ConditionalOnMissingBean(TokenEndpointOrchestrator.class)
    TokenEndpointOrchestrator tokenEndpointOrchestrator(
            @Qualifier("registrationRegistry") RegistrationRegistry registrations, DpopProofValidation proofs,
            DpopStateDigestCapability digests, SecureDpopNonceGenerator nonces, DpopStateStore state,
            AuthorizationCodeRedemption redemptions, AppSubjectResolver subjectResolver, TokenAccessIssuer tokens,
            PlatformTransactionManager transactionManager, TokenEndpointRateLimiter limiter,
            @Value("${iam.dpop.token-target}") String target,
            @Value("${iam.dpop.nonce-lifetime:120s}") Duration nonceLifetime,
            @Value("${iam.dpop.replay-retention:180s}") Duration replayRetention,
            @Value("${iam.dpop.proof-maximum-age-seconds:60}") int proofMaximumAgeSeconds,
            @Value("${iam.dpop.proof-maximum-future-skew-seconds:5}") int proofMaximumFutureSkewSeconds,
            @Value("${iam.token.lifetime:300s}") Duration tokenLifetime,
            ObjectProvider<RefreshTokenRepository> refreshTokens,
            ObjectProvider<RefreshTokenMaterialGenerator> refreshMaterials,
            @Value("${iam.refresh.absolute-lifetime:30d}") Duration refreshAbsoluteLifetime,
            @Value("${iam.refresh.idle-timeout:7d}") Duration refreshIdleTimeout) {
        TokenSubjectResolver subjects = (authorization, correlation) -> subjectResolver.resolve(
                new AppSubjectResolutionCommand(authorization.appRegistrationId(),
                        new IdentityReference(authorization.humanIdentityId()), new CorrelationId(correlation)));
        return new DefaultTokenEndpointOrchestrator(registrations::findByClientId, proofs, digests, nonces, state,
                redemptions::redeem, subjects, tokens,
                new SpringTransactionRunner(new TransactionTemplate(transactionManager)), limiter, target,
                nonceLifetime,
                java.time.Duration.ofSeconds(replayRetentionSeconds(replayRetention, proofMaximumAgeSeconds,
                        proofMaximumFutureSkewSeconds)), tokenLifetime,
                refreshTokens.getIfAvailable(), refreshMaterials.getIfAvailable(),
                refreshAbsoluteLifetime, refreshIdleTimeout);
    }

    @Configuration(proxyBeanMethods = false)
    @Profile("!production & !staging & !production-like")
    static class LocalRateLimitConfiguration {
        @Bean @ConditionalOnMissingBean(TokenEndpointRateLimiter.class)
        TokenEndpointRateLimiter localTokenEndpointRateLimiter() {
            return new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 30, 10, 10_000);
        }
    }

    static int replayRetentionSeconds(Duration retention, int proofMaximumAgeSeconds,
            int proofMaximumFutureSkewSeconds) {
        var value = seconds(retention, 120, 600);
        if (value < proofMaximumAgeSeconds + proofMaximumFutureSkewSeconds + 30) {
            throw new IllegalArgumentException("dpop_replay_retention_too_short");
        }
        return value;
    }

    private static int seconds(Duration value, int minimum, int maximum) {
        if (value == null || value.getNano() != 0 || value.toSeconds() < minimum
                || value.toSeconds() > maximum) {
            throw new IllegalArgumentException("dpop_duration_invalid");
        }
        return Math.toIntExact(value.toSeconds());
    }
}
