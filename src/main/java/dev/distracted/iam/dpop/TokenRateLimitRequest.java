package dev.distracted.iam.dpop;

import java.util.regex.Pattern;

public record TokenRateLimitRequest(@com.fasterxml.jackson.annotation.JsonIgnore String protectedClientBucket,
                                    @com.fasterxml.jackson.annotation.JsonIgnore String protectedNetworkBucket,
                                    TokenRateLimitCategory category) {
    private static final Pattern BUCKET = Pattern.compile("^[A-Za-z0-9_-]{8,128}$");
    public TokenRateLimitRequest {
        if (protectedClientBucket == null || !BUCKET.matcher(protectedClientBucket).matches()
                || protectedNetworkBucket == null || !BUCKET.matcher(protectedNetworkBucket).matches()
                || category == null) throw new IllegalArgumentException("token_rate_limit_request_invalid");
    }
    @Override public String toString() { return "TokenRateLimitRequest[category=" + category + ",redacted]"; }
}
