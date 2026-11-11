package dev.distracted.iam.authorization.refresh;

public enum RefreshRotationOutcome {
    ROTATED,
    INVALID,
    REUSE,
    REVOKED,
    EXPIRED,
    WRONG_KEY,
    SECURITY_VERSION,
    REGISTRATION_CHANGED;

    public static RefreshRotationOutcome of(String value) {
        try {
            return valueOf(value);
        } catch (RuntimeException exception) {
            return INVALID;
        }
    }
}
