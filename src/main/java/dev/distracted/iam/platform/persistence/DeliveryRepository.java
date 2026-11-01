package dev.distracted.iam.platform.persistence;

import dev.distracted.iam.messaging.Delivery;
import dev.distracted.iam.messaging.InitialDelivery;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

public interface DeliveryRepository {
    AppendResult create(InitialDelivery delivery);
    List<Delivery> claim(String owner, Instant now, Duration leaseDuration, int limit);
    boolean acknowledge(String eventId, String destination, String leaseOwner, long expectedVersion, Instant now);
    boolean quarantine(String eventId, String destination, String leaseOwner, long expectedVersion,
            String reasonCode, Instant now);
}
