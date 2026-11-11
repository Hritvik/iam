package dev.distracted.iam.authorization.refresh;

import java.time.Instant;

public record RefreshIssueReceipt(Instant issuedAt, Instant expiresAt, Instant absoluteExpiresAt, long version) {
    public RefreshIssueReceipt {
        if (issuedAt == null || expiresAt == null || absoluteExpiresAt == null
                || !expiresAt.isAfter(issuedAt) || !absoluteExpiresAt.isAfter(issuedAt)
                || !expiresAt.isBefore(absoluteExpiresAt.plusNanos(1)) || version < 1) {
            throw new IllegalArgumentException("refresh_issue_receipt_invalid");
        }
    }
}
