package dev.distracted.iam.identity;

public final class SecretChallengeCode {
    private final char[] value;
    public SecretChallengeCode(String value) { this.value = value.toCharArray(); }
    public String reveal() { return new String(value); }
    @Override public String toString() { return "SecretChallengeCode[protected]"; }
}
