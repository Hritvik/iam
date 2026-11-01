package dev.distracted.iam.dpop.web;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

final class DpopNonceRequiredException extends OAuth2AuthenticationException {
    private final String nonce;
    DpopNonceRequiredException(String nonce) {
        super(new OAuth2Error("use_dpop_nonce"));
        this.nonce = nonce;
    }
    String nonce() { return nonce; }
}
