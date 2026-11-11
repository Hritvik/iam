package dev.distracted.iam.dpop;

public sealed interface TokenEndpointOutcome {
    record Challenge(@com.fasterxml.jackson.annotation.JsonIgnore String nonce) implements TokenEndpointOutcome {
        @Override public String toString() { return "Challenge[redacted]"; }
    }
    record Success(@com.fasterxml.jackson.annotation.JsonIgnore String accessToken,
                   long expiresIn, String scope,
                   @com.fasterxml.jackson.annotation.JsonIgnore String refreshToken) implements TokenEndpointOutcome {
        public Success(String accessToken, long expiresIn, String scope) {
            this(accessToken, expiresIn, scope, null);
        }

        @Override public String toString() { return "Success[expiresIn=" + expiresIn + ",redacted]"; }
    }
}
