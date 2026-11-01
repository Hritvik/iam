package dev.distracted.iam.messaging.relay;

public interface OutboxTransport {
    void publish(OutboxEnvelope envelope);
}
