package dev.distracted.iam.authorization;

import dev.distracted.iam.identity.IdentityReference;
import java.security.Principal;
import java.util.Objects;

public record IamIdentityPrincipal(IdentityReference identity) implements Principal {
    public IamIdentityPrincipal { Objects.requireNonNull(identity, "identity"); }
    @Override public String getName() { return identity.identityId(); }
    @Override public String toString() { return "IamIdentityPrincipal[protected]"; }
}
