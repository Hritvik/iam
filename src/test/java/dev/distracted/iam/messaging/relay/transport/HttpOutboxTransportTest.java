package dev.distracted.iam.messaging.relay.transport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import dev.distracted.iam.messaging.relay.NonRetryableTransportException;
import dev.distracted.iam.messaging.relay.OutboxEnvelope;
import dev.distracted.iam.messaging.relay.TransportException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class HttpOutboxTransportTest {
    private static final OutboxEnvelope ENVELOPE = new OutboxEnvelope(
            "evt_0123456789abcdef", "iam.app-subject.onboarding-ready.v1", 1,
            Instant.parse("2026-11-08T00:00:00Z"), "iam", "development", "APP_ONBOARDING",
            "act_0123456789abcdef", 1, "cor_0123456789abcdef", null, "dutch-development",
            "{\"appRegistrationId\":\"dutch-development\"}", "a".repeat(64));

    @Test
    void postsThePublishedEnvelopeWithWorkloadAuthorization() throws Exception {
        var body = new AtomicReference<String>();
        var authorization = new AtomicReference<String>();
        var idempotency = new AtomicReference<String>();
        var correlation = new AtomicReference<String>();
        try (var server = server(202, exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            idempotency.set(exchange.getRequestHeaders().getFirst("Idempotency-Key"));
            correlation.set(exchange.getRequestHeaders().getFirst("X-Correlation-ID"));
        })) {
            transport(server, () -> "workload-token").publish(ENVELOPE);

            assertThat(authorization.get()).isEqualTo("Bearer workload-token");
            assertThat(idempotency.get()).isEqualTo("evt_0123456789abcdef");
            assertThat(correlation.get()).isEqualTo("cor_0123456789abcdef");
            var json = new ObjectMapper().readTree(body.get());
            assertThat(json.required("eventId").textValue()).isEqualTo("evt_0123456789abcdef");
            assertThat(json.required("destination").required("appRegistrationId").textValue())
                    .isEqualTo("dutch-development");
            assertThat(json.required("payload").required("appRegistrationId").textValue())
                    .isEqualTo("dutch-development");
            assertThat(json.required("occurredAt").textValue()).isEqualTo("2026-11-08T00:00:00Z");
        }
    }

    @Test
    void retriesTransportFailuresAndQuarantinesContractFailures() throws Exception {
        try (var server = server(503, exchange -> { })) {
            assertThatThrownBy(() -> transport(server, () -> "token").publish(ENVELOPE))
                    .isInstanceOf(TransportException.class)
                    .isNotInstanceOf(NonRetryableTransportException.class);
        }
        try (var server = server(422, exchange -> { })) {
            assertThatThrownBy(() -> transport(server, () -> "token").publish(ENVELOPE))
                    .isInstanceOf(NonRetryableTransportException.class);
        }
        try (var server = server(429, exchange -> { })) {
            assertThatThrownBy(() -> transport(server, () -> "token").publish(ENVELOPE))
                    .isInstanceOf(TransportException.class)
                    .isNotInstanceOf(NonRetryableTransportException.class);
        }
    }

    @Test
    void acceptsEveryTwoHundredFamilyStatusAndRetries408() throws Exception {
        for (var status : new int[] {200, 201, 204}) {
            try (var server = server(status, exchange -> { })) {
                transport(server, () -> "token").publish(ENVELOPE);
            }
        }
        try (var server = server(408, exchange -> { })) {
            assertThatThrownBy(() -> transport(server, () -> "token").publish(ENVELOPE))
                    .isInstanceOf(TransportException.class)
                    .isNotInstanceOf(NonRetryableTransportException.class);
        }
        try (var server = server(400, exchange -> { })) {
            assertThatThrownBy(() -> transport(server, () -> "token").publish(ENVELOPE))
                    .isInstanceOf(NonRetryableTransportException.class);
        }
    }

    @Test
    void treatsAnUnreachableConsumerAsARetryableTransportFailure() {
        var transport = new HttpOutboxTransport(
                URI.create("http://127.0.0.1:1/events"), HttpClient.newHttpClient(), () -> "token",
                Duration.ofSeconds(1));
        assertThatThrownBy(() -> transport.publish(ENVELOPE)).isInstanceOf(TransportException.class);
    }

    @Test
    void refusesAnUnusableToken() throws Exception {
        try (var server = server(200, exchange -> { })) {
            assertThatThrownBy(() -> transport(server, () -> " ").publish(ENVELOPE))
                    .isInstanceOf(TransportException.class);
            assertThatThrownBy(() -> transport(server, () -> null).publish(ENVELOPE))
                    .isInstanceOf(TransportException.class);
        }
    }

    @Test
    void refusesUnsafeOrUnboundedConfiguration() {
        assertThatThrownBy(() -> new HttpOutboxTransport(
                URI.create("http://ums.internal/events"), HttpClient.newHttpClient(), () -> "token",
                Duration.ofSeconds(2)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relay_transport_endpoint_insecure");
        for (var endpoint : new String[] {
                "https://user@ums.invalid/events",
                "https://ums.invalid/events?debug=true",
                "https://ums.invalid/events#fragment"}) {
            assertThatThrownBy(() -> new HttpOutboxTransport(
                    URI.create(endpoint), HttpClient.newHttpClient(), () -> "token", Duration.ofSeconds(2)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("relay_transport_endpoint_invalid");
        }
        assertThatThrownBy(() -> new HttpOutboxTransport(
                null, HttpClient.newHttpClient(), () -> "token", Duration.ofSeconds(2)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relay_transport_endpoint_invalid");
        assertThatThrownBy(() -> new HttpOutboxTransport(
                URI.create("https:///events"), HttpClient.newHttpClient(), () -> "token", Duration.ofSeconds(2)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relay_transport_endpoint_invalid");
        assertThatThrownBy(() -> new HttpOutboxTransport(
                URI.create("https://ums.invalid/events"), HttpClient.newHttpClient(), () -> "token",
                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relay_transport_timeout_invalid");
        assertThatThrownBy(() -> new HttpOutboxTransport(
                URI.create("https://ums.invalid/events"), HttpClient.newHttpClient(), () -> "token",
                Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relay_transport_timeout_invalid");
        assertThatThrownBy(() -> new HttpOutboxTransport(
                URI.create("https://ums.invalid/events"), HttpClient.newHttpClient(), () -> "token",
                Duration.ofSeconds(61)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relay_transport_timeout_invalid");
    }

    private static HttpOutboxTransport transport(TestServer server, WorkloadTokenSupplier tokens) {
        return new HttpOutboxTransport(
                URI.create("http://127.0.0.1:" + server.getAddressPort() + "/events"),
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build(),
                tokens,
                Duration.ofSeconds(2));
    }

    private interface Handler {
        void handle(com.sun.net.httpserver.HttpExchange exchange) throws Exception;
    }

    private static TestServer server(int status, Handler handler) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/events", exchange -> {
            try {
                handler.handle(exchange);
                exchange.sendResponseHeaders(status, -1);
            } catch (Exception exception) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
        return new TestServer(server);
    }

    private record TestServer(HttpServer server) implements AutoCloseable {
        int getAddressPort() {
            return server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
