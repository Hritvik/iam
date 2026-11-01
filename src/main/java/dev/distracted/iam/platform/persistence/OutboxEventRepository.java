package dev.distracted.iam.platform.persistence;

import dev.distracted.iam.messaging.OutboxEvent;

public interface OutboxEventRepository {
    AppendResult append(OutboxEvent event);
}
