package dev.distracted.iam.messaging.relay;

public class TransportException extends RuntimeException {
    public TransportException() { super("outbox_transport_unavailable"); }
    public TransportException(Throwable cause) { super("outbox_transport_unavailable", cause); }
}
