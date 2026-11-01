package dev.distracted.iam.dpop;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public final class BoundedLocalTokenEndpointRateLimiter implements TokenEndpointRateLimiter {
    private final Clock clock;
    private final int challengeLimit;
    private final int retryLimit;
    private final int maximumKeys;
    private final Map<String, Bucket> buckets;
    public BoundedLocalTokenEndpointRateLimiter(Clock clock, int challengeLimit, int retryLimit, int maximumKeys) {
        this.clock = java.util.Objects.requireNonNull(clock);
        if (challengeLimit < 1 || challengeLimit > 1000 || retryLimit < 1 || retryLimit > 1000
                || maximumKeys < 1 || maximumKeys > 100_000) {
            throw new IllegalArgumentException("token_rate_limit_invalid");
        }
        this.challengeLimit = challengeLimit;
        this.retryLimit = retryLimit;
        this.maximumKeys = maximumKeys;
        this.buckets = new LinkedHashMap<>(16, 0.75f, true);
    }
    @Override public synchronized boolean allow(TokenRateLimitRequest request) {
        if (request == null) return false;
        var key = request.category() + "|" + request.protectedClientBucket() + "|" + request.protectedNetworkBucket();
        var minute = Instant.now(clock).getEpochSecond() / 60;
        var bucket = buckets.get(key);
        if (bucket == null || bucket.minute != minute) {
            if (bucket == null && buckets.size() >= maximumKeys) {
                buckets.remove(buckets.keySet().iterator().next());
            }
            buckets.put(key, new Bucket(minute, 1));
            return true;
        }
        var limit = request.category() == TokenRateLimitCategory.CHALLENGE ? challengeLimit : retryLimit;
        if (bucket.count >= limit) return false;
        buckets.put(key, new Bucket(minute, bucket.count + 1));
        return true;
    }
    private record Bucket(long minute, int count) { }
}
