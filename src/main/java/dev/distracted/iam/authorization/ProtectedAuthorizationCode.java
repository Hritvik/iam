package dev.distracted.iam.authorization;

public record ProtectedAuthorizationCode(short keyVersion, byte[] digest) {
    public ProtectedAuthorizationCode {
        digest = digest.clone();
    }

    @Override public byte[] digest() { return digest.clone(); }
    @Override public String toString() { return "ProtectedAuthorizationCode[keyVersion=" + keyVersion + ",protected]"; }
}
