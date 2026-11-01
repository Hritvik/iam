package dev.distracted.iam.dpop;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.token.DpopKeyThumbprint;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class DeadlineTokenAccessIssuer implements TokenAccessIssuer, AutoCloseable {
    private final TokenAccessIssuer delegate;
    private final long timeoutMillis;
    private final ThreadPoolExecutor executor;
    public DeadlineTokenAccessIssuer(TokenAccessIssuer delegate, Duration timeout, int workers, int queuedCalls) {
        this.delegate = java.util.Objects.requireNonNull(delegate);
        if (timeout == null || timeout.compareTo(Duration.ofMillis(10)) < 0
                || timeout.compareTo(Duration.ofSeconds(5)) > 0 || workers < 1 || workers > 16
                || queuedCalls < 1 || queuedCalls > 1000) {
            throw new IllegalArgumentException("token_signing_deadline_invalid");
        }
        this.timeoutMillis = timeout.toMillis();
        this.executor = new ThreadPoolExecutor(workers, workers, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queuedCalls), runnable -> {
                    var thread = new Thread(runnable, "iam-token-signer");
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    @Override public String issue(ConsumedAuthorization authorization, AppSubject subject, int securityVersion,
            DpopKeyThumbprint thumbprint, String correlationId, RegistrationManifest registration) {
        java.util.concurrent.Future<String> future = null;
        try {
            future = executor.submit(() -> delegate.issue(authorization, subject, securityVersion,
                    thumbprint, correlationId, registration));
            return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException exception) {
            throw unavailableAfterCancel(future);
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.RejectedExecutionException exception) {
            throw new IllegalStateException("token_signing_unavailable");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("token_signing_unavailable");
        }
    }

    private IllegalStateException unavailableAfterCancel(java.util.concurrent.Future<String> future) {
        if (future != null) future.cancel(true);
        return new IllegalStateException("token_signing_unavailable");
    }

    @Override public void close() { executor.shutdownNow(); }
}
