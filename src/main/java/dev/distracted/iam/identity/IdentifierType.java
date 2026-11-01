package dev.distracted.iam.identity;

public enum IdentifierType {
    EMAIL("email"), PHONE("phone");

    private final String wireValue;

    IdentifierType(String wireValue) { this.wireValue = wireValue; }

    public String wireValue() { return wireValue; }
}
