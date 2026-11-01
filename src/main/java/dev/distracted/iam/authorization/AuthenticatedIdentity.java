package dev.distracted.iam.authorization;

import dev.distracted.iam.identity.IdentityReference;
import java.util.Objects;

public record AuthenticatedIdentity(IdentityReference identity) {
    public AuthenticatedIdentity { Objects.requireNonNull(identity, "identity"); }
}
