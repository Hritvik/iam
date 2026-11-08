package dev.distracted.iam.messaging.relay.transport;

import dev.distracted.iam.messaging.relay.NonRetryableTransportException;
import dev.distracted.iam.messaging.relay.OutboxEnvelope;
import dev.distracted.iam.messaging.relay.OutboxTransport;
import dev.distracted.iam.messaging.relay.TransportException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Publishes outbox envelopes over HTTPS as the published event envelope, authenticated with a
 * workload access token.
 *
 * <p>Only transport failures are retried. A 4xx other than 408/429 is a consumer contract failure
 * and goes straight to quarantine.
 */
public final class HttpOutboxTransport implements OutboxTransport {
    private final URI endpoint;
    private final HttpClient client;
    private final WorkloadTokenSupplier tokens;
    private final Duration requestTimeout;

    public HttpOutboxTransport(
            URI endpoint,
            HttpClient client,
            WorkloadTokenSupplier tokens,
            Duration requestTimeout) {
        this.endpoint = requireEndpoint(endpoint);
        this.client = Objects.requireNonNull(client);
        this.tokens = Objects.requireNonNull(tokens);
        if (requestTimeout == null || requestTimeout.isZero() || requestTimeout.isNegative()
                || requestTimeout.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("relay_transport_timeout_invalid");
        }
        this.requestTimeout = requestTimeout;
    }

    @Override
    public void publish(OutboxEnvelope envelope) {
        final String token;
        try {
            token = tokens.token();
        } catch (RuntimeException exception) {
            throw new TransportException(exception);
        }
        if (token == null || token.isBlank()) {
            throw new TransportException();
        }
        var request = HttpRequest.newBuilder(endpoint)
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + token)
                .header("Idempotency-Key", envelope.eventId())
                .header("X-Correlation-ID", envelope.correlationId())
                .POST(HttpRequest.BodyPublishers.ofByteArray(OutboxEnvelopeJson.toWire(envelope)))
                .build();
        final HttpResponse<Void> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (IOException exception) {
            throw new TransportException(exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new TransportException(exception);
        }
        var status = response.statusCode();
        if (status >= 200 && status < 300) {
            return;
        }
        if (status == 401 || status == 403 || status == 404 || status == 408 || status == 429 || status >= 500) {
            throw new TransportException();
        }
        throw new NonRetryableTransportException();
    }

    private static URI requireEndpoint(URI endpoint) {
        if (endpoint == null || endpoint.getHost() == null || endpoint.getUserInfo() != null
                || endpoint.getFragment() != null || endpoint.getQuery() != null) {
            throw new IllegalArgumentException("relay_transport_endpoint_invalid");
        }
        var scheme = endpoint.getScheme();
        var host = endpoint.getHost();
        var loopback = "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host)
                || "::1".equals(host);
        if (!"https".equals(scheme) && !("http".equals(scheme) && loopback)) {
            throw new IllegalArgumentException("relay_transport_endpoint_insecure");
        }
        return endpoint;
    }
}
