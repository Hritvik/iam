package dev.distracted.iam.messaging;

import java.time.Instant;

public record Delivery(String eventId, String destinationName, String state, int attemptCount,
        Instant availableAt, String leaseOwner, Instant leaseExpiresAt, Instant acknowledgedAt,
        String lastFailureCode, long version) {}
