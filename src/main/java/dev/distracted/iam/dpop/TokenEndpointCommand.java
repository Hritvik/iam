package dev.distracted.iam.dpop;

import com.fasterxml.jackson.annotation.JsonIgnore;

public record TokenEndpointCommand(@JsonIgnore String grantType, @JsonIgnore String code,
                                   @JsonIgnore String redirectUri, @JsonIgnore String clientId,
                                   @JsonIgnore String codeVerifier, @JsonIgnore String dpopProof,
                                   @JsonIgnore String correlationId, @JsonIgnore String trustedNetworkContext,
                                   @JsonIgnore String refreshToken) {
    public TokenEndpointCommand(String grantType, String code, String redirectUri, String clientId,
            String codeVerifier, String dpopProof, String correlationId) {
        this(grantType, code, redirectUri, clientId, codeVerifier, dpopProof, correlationId,
                "unknown-network", null);
    }

    public TokenEndpointCommand(String grantType, String code, String redirectUri, String clientId,
            String codeVerifier, String dpopProof, String correlationId, String trustedNetworkContext) {
        this(grantType, code, redirectUri, clientId, codeVerifier, dpopProof, correlationId,
                trustedNetworkContext, null);
    }
    public TokenEndpointCommand {
        if (trustedNetworkContext == null || trustedNetworkContext.isBlank()
                || trustedNetworkContext.length() > 128) {
            throw new IllegalArgumentException("trusted_network_context_invalid");
        }
    }
    @Override public String toString() { return "TokenEndpointCommand[redacted]"; }
}
