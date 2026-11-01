package dev.distracted.iam.messaging.relay;

public final class RelayException extends RuntimeException {
    public RelayException() { super("outbox_relay_unavailable"); }
    public RelayException(Throwable cause) { super("outbox_relay_unavailable", cause); }
}
