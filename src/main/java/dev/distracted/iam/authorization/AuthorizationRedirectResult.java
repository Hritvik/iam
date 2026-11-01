package dev.distracted.iam.authorization;

import java.time.Instant;

public record AuthorizationRedirectResult(
        String redirectUri, String code, String state, Instant issuedAt, Instant expiresAt) { }
