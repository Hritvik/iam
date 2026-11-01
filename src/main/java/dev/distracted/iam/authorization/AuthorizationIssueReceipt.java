package dev.distracted.iam.authorization;

import java.time.Instant;

public record AuthorizationIssueReceipt(Instant issuedAt, Instant expiresAt, long version) { }
