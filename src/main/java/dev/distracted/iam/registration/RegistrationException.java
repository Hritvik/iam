package dev.distracted.iam.registration;

public final class RegistrationException extends RuntimeException {
    public RegistrationException(String safeCode) { super(safeCode); }

    public RegistrationException(String safeCode, Throwable cause) { super(safeCode, cause); }
}
