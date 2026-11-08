package dev.distracted.iam.messaging.relay.transport;

@FunctionalInterface
public interface WorkloadTokenSupplier {
    String token();
}
