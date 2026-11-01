package dev.distracted.iam.identity;

public final class IdentifierCryptoException extends IllegalStateException {
    public IdentifierCryptoException() { super("identifier_crypto_failed"); }
}
