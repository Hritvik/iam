package dev.distracted.iam.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record AuthorizationServerMetadata(
        String issuer,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported,
        @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("dpop_signing_alg_values_supported") List<String> dpopSigningAlgValuesSupported) {
    public AuthorizationServerMetadata {
        responseTypesSupported = List.copyOf(responseTypesSupported);
        grantTypesSupported = List.copyOf(grantTypesSupported);
        codeChallengeMethodsSupported = List.copyOf(codeChallengeMethodsSupported);
        tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
        dpopSigningAlgValuesSupported = List.copyOf(dpopSigningAlgValuesSupported);
    }

    public static AuthorizationServerMetadata of(String issuer) {
        return new AuthorizationServerMetadata(issuer, issuer + "/oauth2/authorize", issuer + "/oauth2/token",
                issuer + "/oauth2/jwks", List.of("code"), List.of("authorization_code"), List.of("S256"),
                List.of("none"), List.of("ES256"));
    }
}
