package dev.distracted.iam.platform.persistence;

import dev.distracted.iam.messaging.AuditFact;

public interface AuditFactRepository {
    AppendResult append(AuditFact fact);
}
