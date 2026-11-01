package dev.distracted.iam.messaging;

import java.time.Instant;

public record InitialDelivery(String eventId, Instant availableAt) {
    public InitialDelivery {
        if (eventId == null || !eventId.matches("^evt_[A-Za-z0-9_-]{16,128}$")
                || availableAt == null) {
            throw new IllegalArgumentException("initial delivery is invalid");
        }
    }
}
