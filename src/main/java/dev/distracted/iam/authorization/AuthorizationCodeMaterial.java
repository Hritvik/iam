package dev.distracted.iam.authorization;

public record AuthorizationCodeMaterial(String codeId, byte[] randomValue) {
    public AuthorizationCodeMaterial { randomValue = randomValue.clone(); }
    @Override public byte[] randomValue() { return randomValue.clone(); }
    @Override public String toString() { return "AuthorizationCodeMaterial[codeId=" + codeId + ",protected]"; }
}
