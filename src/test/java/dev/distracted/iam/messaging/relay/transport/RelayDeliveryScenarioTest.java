package dev.distracted.iam.messaging.relay.transport;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import dev.distracted.iam.messaging.relay.ClaimedDelivery;
import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.OutboxEnvelope;
import dev.distracted.iam.messaging.relay.OutboxRelayRepository;
import dev.distracted.iam.messaging.relay.RelaySettings;
import dev.distracted.iam.token.SecureAccessTokenMaterialGenerator;
import dev.distracted.iam.workload.WorkloadAccessTokenIssuer;
import dev.distracted.iam.workload.WorkloadIdentityProperties;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * Proves the relay delivery contract: distinct events, a lost response retried with the same event id
 * but a fresh credential, a duplicate delivery, and acknowledgement only after a 2xx.
 */
class RelayDeliveryScenarioTest {
    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");
    private static final String APP = "dutch-development";
    private static final String AUDIENCE = "https://ums.localhost/internal/v1/iam/events";
    private static final String WORKLOAD_ID = "wl_0123456789abcdefghijklmnop";
    private static final RelaySettings SETTINGS = new RelaySettings("relay-1", 30, 10, 2);

    private final List<String> order = new ArrayList<>();
    private final List<Request> requests = new ArrayList<>();
    private final AtomicInteger lostResponse = new AtomicInteger(1);

    @Test
    void deliversDistinctEventsRetriesALostResponseAndKeepsIdempotencyOnDuplicate() throws Exception {
        var repository = new QueueRepository();
        repository.queue(List.of(delivery("evt_a0123456789abcdef", 1), delivery("evt_b0123456789abcdef", 1),
                delivery("evt_c0123456789abcdef", 1)));
        var server = consumer();
        try {
            var relay = relay(server, repository);
            relay.drainOnce();

            assertThat(repository.acknowledged).containsExactly("evt_a0123456789abcdef", "evt_b0123456789abcdef");
            assertThat(requests).extracting(Request::eventId)
                    .containsExactly("evt_a0123456789abcdef", "evt_b0123456789abcdef", "evt_c0123456789abcdef");

            repository.queue(List.of(delivery("evt_c0123456789abcdef", 2),
                    delivery("evt_a0123456789abcdef", 1)));
            relay.drainOnce();

            var c = requests.stream().filter(request -> request.eventId().equals("evt_c0123456789abcdef"))
                    .toList();
            assertThat(c).hasSize(2);
            assertThat(c.get(0).idempotencyKey()).isEqualTo(c.get(1).idempotencyKey());
            assertThat(c.get(0).jti()).isNotEqualTo(c.get(1).jti());
            assertThat(repository.acknowledged).contains("evt_c0123456789abcdef");
            assertThat(repository.quarantined).isEmpty();

            var a = requests.stream().filter(request -> request.eventId().equals("evt_a0123456789abcdef"))
                    .toList();
            assertThat(a).hasSize(2);
            assertThat(a.get(0).idempotencyKey()).isEqualTo(a.get(1).idempotencyKey());

            assertThat(order).containsSubsequence(
                    "post:evt_a0123456789abcdef", "ack:evt_a0123456789abcdef",
                    "post:evt_c0123456789abcdef", "ack:evt_c0123456789abcdef");
        } finally {
            server.server().stop(0);
        }
    }

    private OnboardingRelay relay(TestServer server, QueueRepository repository) throws Exception {
        var transport = new HttpOutboxTransport(
                URI.create("http://127.0.0.1:" + server.server().getAddress().getPort() + "/events"),
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build(),
                new SelfIssuedWorkloadTokenSupplier(issuer(), WORKLOAD_ID, AUDIENCE, "ums:onboarding:write"),
                Duration.ofSeconds(2));
        return new OnboardingRelay(repository, transport, SETTINGS, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private TestServer consumer() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/events", exchange -> {
            try {
                var body = new ObjectMapper().readTree(exchange.getRequestBody().readAllBytes());
                var eventId = body.required("eventId").textValue();
                var idempotencyKey = exchange.getRequestHeaders().getFirst("Idempotency-Key");
                var authorization = exchange.getRequestHeaders().getFirst("Authorization");
                requests.add(new Request(eventId, idempotencyKey, jti(authorization)));
                order.add("post:" + eventId);
                var status = eventId.startsWith("evt_c") && lostResponse.getAndDecrement() > 0 ? 500 : 200;
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

    private WorkloadAccessTokenIssuer issuer() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        var properties = new WorkloadIdentityProperties(
                true,
                "https://iam.distracted.invalid",
                300,
                30,
                new WorkloadIdentityProperties.Signing(
                        "workload-key-1",
                        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())),
                List.of(new WorkloadIdentityProperties.TrustedKey(
                        "workload-key-1", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()))),
                List.of(new WorkloadIdentityProperties.Binding(
                        WORKLOAD_ID, APP, "iam-relay", List.of(AUDIENCE), List.of("ums:onboarding:write"))));
        return new WorkloadAccessTokenIssuer(
                properties, new SecureAccessTokenMaterialGenerator(new SecureRandom()),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static String jti(String authorization) throws Exception {
        var token = authorization.substring("Bearer ".length());
        var payload = token.split("\\.")[1];
        var json = new ObjectMapper().readTree(new String(Base64.getUrlDecoder().decode(payload),
                StandardCharsets.UTF_8));
        return json.required("jti").textValue();
    }

    private static ClaimedDelivery delivery(String eventId, int attempt) {
        return new ClaimedDelivery(eventId, "dutch-ums-onboarding", attempt, 1);
    }

    private record Request(String eventId, String idempotencyKey, String jti) {
    }

    private record TestServer(HttpServer server) {
    }

    private final class QueueRepository implements OutboxRelayRepository {
        private final Map<String, OutboxEnvelope> events = new HashMap<>();
        private final List<ClaimedDelivery> queue = new ArrayList<>();
        final List<String> acknowledged = new ArrayList<>();
        final List<String> quarantined = new ArrayList<>();

        void queue(List<ClaimedDelivery> deliveries) {
            queue.clear();
            queue.addAll(deliveries);
            for (var delivery : deliveries) {
                events.putIfAbsent(delivery.eventId(), envelope(delivery.eventId()));
            }
        }

        @Override
        public List<ClaimedDelivery> claim(String owner, Instant now, int lease, int limit) {
            var claimed = List.copyOf(queue);
            queue.clear();
            return claimed;
        }

        @Override
        public Optional<OutboxEnvelope> event(String eventId) {
            return Optional.ofNullable(events.get(eventId));
        }

        @Override
        public boolean acknowledge(String eventId, String destination, String owner, long version, Instant now) {
            acknowledged.add(eventId);
            order.add("ack:" + eventId);
            return true;
        }

        @Override
        public boolean quarantine(String eventId, String destination, String owner, long version, String reason,
                                  Instant now) {
            quarantined.add(eventId + ":" + reason);
            return true;
        }

        @Override
        public void appendQuarantineAudit(String auditId, String eventId, String correlationId, String reason,
                                          Instant occurredAt) {
        }

        private OutboxEnvelope envelope(String eventId) {
            return new OutboxEnvelope(eventId, "iam.app-subject.onboarding-ready.v1", 1, NOW, "iam",
                    "development", "APP_ONBOARDING", "act_0123456789abcdef", 1,
                    "cor_0123456789abcdef", null, APP, "{\"appRegistrationId\":\"dutch-development\"}",
                    "a".repeat(64));
        }
    }
}
