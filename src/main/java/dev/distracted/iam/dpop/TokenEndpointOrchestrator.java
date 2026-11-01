package dev.distracted.iam.dpop;

public interface TokenEndpointOrchestrator {
    TokenEndpointOutcome exchange(TokenEndpointCommand command);
}
