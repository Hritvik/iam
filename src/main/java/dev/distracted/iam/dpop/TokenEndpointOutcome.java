package dev.distracted.iam.dpop;

public sealed interface TokenEndpointOutcome {
    record Challenge(@com.fasterxml.jackson.annotation.JsonIgnore String nonce) implements TokenEndpointOutcome {
        @Override public String toString() { return "Challenge[redacted]"; }
    }
    record Success(@com.fasterxml.jackson.annotation.JsonIgnore String accessToken,
                   long expiresIn, String scope) implements TokenEndpointOutcome {
        @Override public String toString() { return "Success[expiresIn=" + expiresIn + ",redacted]"; }
    }
}
