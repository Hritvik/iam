package dev.distracted.iam.dpop;

import java.util.Set;

public record VerifiedDpopPrincipal(String appSubject, String appRegistrationId, String clientId,
        String audience, Set<String> scopes, int securityVersion) {
    public VerifiedDpopPrincipal { scopes = Set.copyOf(scopes); }
    @Override public String toString() { return "VerifiedDpopPrincipal[redacted]"; }
}
