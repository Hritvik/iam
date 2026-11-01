package dev.distracted.iam.dpop;

@FunctionalInterface
public interface TokenEndpointRateLimiter { boolean allow(TokenRateLimitRequest request); }
