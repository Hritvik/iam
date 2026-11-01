package dev.distracted.iam.dpop.web;

import dev.distracted.iam.dpop.TokenEndpointCommand;
import dev.distracted.iam.dpop.TokenEndpointOutcome;
import org.springframework.security.authentication.AbstractAuthenticationToken;

final class DpopTokenRequestAuthenticationToken extends AbstractAuthenticationToken {
    private final TokenEndpointCommand command;
    private final TokenEndpointOutcome outcome;

    DpopTokenRequestAuthenticationToken(TokenEndpointCommand command) {
        super(java.util.List.of());
        this.command = command;
        this.outcome = null;
        setAuthenticated(false);
    }

    DpopTokenRequestAuthenticationToken(TokenEndpointCommand command, TokenEndpointOutcome outcome) {
        super(java.util.List.of());
        this.command = command;
        this.outcome = outcome;
        setAuthenticated(true);
    }

    TokenEndpointCommand command() { return command; }
    TokenEndpointOutcome outcome() { return outcome; }
    @Override public Object getCredentials() { return "[redacted]"; }
    @Override public Object getPrincipal() { return command.clientId(); }
    @Override public String toString() { return "DpopTokenRequestAuthenticationToken[redacted]"; }
}
