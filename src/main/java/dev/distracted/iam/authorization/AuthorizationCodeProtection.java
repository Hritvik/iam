package dev.distracted.iam.authorization;

public record AuthorizationCodeProtection(short keyVersion, byte[] digest, long version) {
    public AuthorizationCodeProtection { digest = digest.clone(); }
    @Override public byte[] digest() { return digest.clone(); }
    @Override public String toString() { return "AuthorizationCodeProtection[keyVersion=" + keyVersion + ",version=" + version + ",protected]"; }
}
