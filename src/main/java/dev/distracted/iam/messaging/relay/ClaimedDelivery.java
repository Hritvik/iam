package dev.distracted.iam.messaging.relay;

public record ClaimedDelivery(String eventId, String destinationName, int attemptCount, long version) {
}
