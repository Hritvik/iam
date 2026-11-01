package dev.distracted.iam.platform.crypto;

public final class SealedIdentifierValue {
    private final byte[] ciphertext;
    private final byte[] nonce;
    private final byte[] tag;
    private final short keyVersion;

    public SealedIdentifierValue(byte[] ciphertext, byte[] nonce, byte[] tag, short keyVersion) {
        this.ciphertext = require(ciphertext, 1, "ciphertext");
        this.nonce = require(nonce, 12, "nonce");
        this.tag = require(tag, 16, "tag");
        if (keyVersion < 1) throw new IllegalArgumentException("key_version_invalid");
        this.keyVersion = keyVersion;
    }

    private static byte[] require(byte[] value, int minimum, String field) {
        if (value == null || value.length < minimum) throw new IllegalArgumentException(field + "_invalid");
        return value.clone();
    }

    public byte[] ciphertext() { return ciphertext.clone(); }
    public byte[] nonce() { return nonce.clone(); }
    public byte[] tag() { return tag.clone(); }
    public short keyVersion() { return keyVersion; }
    @Override public String toString() { return "SealedIdentifierValue[protected]"; }
}
