package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import dev.distracted.iam.token.DpopKeyThumbprint;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DeadlineTokenAccessIssuerTest {
    @Test void signerTimeoutFailsClosedAndInterruptsTheBoundedWorker() throws Exception {
        var interrupted = new CountDownLatch(1);
        TokenAccessIssuer blocking = (authorization, subject, version, thumbprint, correlation, registration) -> {
            try {
                Thread.sleep(Duration.ofSeconds(30));
                return "must-not-return";
            } catch (InterruptedException exception) {
                interrupted.countDown();
                Thread.currentThread().interrupt();
                throw new IllegalStateException("provider-secret-detail");
            }
        };
        try (var issuer = new DeadlineTokenAccessIssuer(blocking, Duration.ofMillis(25), 1, 1)) {
            assertThatThrownBy(() -> issuer.issue(authorization(), new AppSubject("aps_abcdefghijklmnopqrstuvwx"), 1,
                    new DpopKeyThumbprint(java.util.Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(new byte[32])), "cor_abcdefghijklmnop", null))
                    .isInstanceOf(IllegalStateException.class).hasMessage("token_signing_unavailable")
                    .hasMessageNotContaining("provider");
            assertThat(interrupted.await(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test void returnsTheSignedTokenWhenTheSignerCompletesBeforeTheDeadline() {
        try (var issuer = new DeadlineTokenAccessIssuer((authorization, subject, version, thumbprint, correlation, registration) ->
                "compact.access.token", Duration.ofMillis(500), 1, 1)) {
            assertThat(issuer.issue(authorization(), new AppSubject("aps_abcdefghijklmnopqrstuvwx"), 1,
                    new DpopKeyThumbprint(java.util.Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(new byte[32])), "cor_abcdefghijklmnop", null)).isEqualTo("compact.access.token");
        }
    }

    @Test void rejectsNonpositiveExcessiveAndOutOfRangeBounds() {
        TokenAccessIssuer noop = (authorization, subject, version, thumbprint, correlation, registration) -> "token";
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ZERO, 1, 1))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("token_signing_deadline_invalid");
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ofMillis(9), 1, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ofSeconds(6), 1, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ofMillis(50), 0, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ofMillis(50), 17, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ofMillis(50), 1, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DeadlineTokenAccessIssuer(noop, Duration.ofMillis(50), 1, 1001))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void anInterruptIgnoringSignerCannotAccumulateBeyondWorkersPlusQueue() throws Exception {
        var release = new CountDownLatch(1);
        var started = new AtomicInteger();
        TokenAccessIssuer stubborn = (authorization, subject, version, thumbprint, correlation, registration) -> {
            started.incrementAndGet();
            while (true) {
                try {
                    release.await();
                    return "must-not-return";
                } catch (InterruptedException ignored) {
                    // deliberately non-cooperative: the pool, not the signer, must bound resources
                }
            }
        };
        try (var issuer = new DeadlineTokenAccessIssuer(stubborn, Duration.ofMillis(25), 1, 1)) {
            assertThatThrownBy(() -> issueWith(issuer)).isInstanceOf(IllegalStateException.class)
                    .hasMessage("token_signing_unavailable");
            assertThatThrownBy(() -> issueWith(issuer)).isInstanceOf(IllegalStateException.class);
            // worker busy + queue full: the next submission must be rejected, not queued
            assertThatThrownBy(() -> issueWith(issuer)).isInstanceOf(IllegalStateException.class)
                    .hasMessage("token_signing_unavailable");
            assertThat(started.get()).isLessThanOrEqualTo(2);
        } finally {
            release.countDown();
        }
    }

    private void issueWith(DeadlineTokenAccessIssuer issuer) {
        issuer.issue(authorization(), new AppSubject("aps_abcdefghijklmnopqrstuvwx"), 1,
                new DpopKeyThumbprint(java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(new byte[32])), "cor_abcdefghijklmnop", null);
    }

    private static ConsumedAuthorization authorization() {
        return new ConsumedAuthorization("arq_abcdefghijklmnopqrstuv", "dutch-development", "dutch-mobile",
                "dutch-api", "https://api.dutch.example", "hid_abcdefghijklmnopqrstuv", "member:read",
                new byte[32], new byte[32]);
    }
}
