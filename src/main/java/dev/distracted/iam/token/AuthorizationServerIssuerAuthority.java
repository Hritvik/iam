package dev.distracted.iam.token;

/** Supplies the migration-owned singleton issuer through a trusted internal authority. */
public interface AuthorizationServerIssuerAuthority {
    String pinnedIssuer();
}
