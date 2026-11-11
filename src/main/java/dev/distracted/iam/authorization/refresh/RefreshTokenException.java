package dev.distracted.iam.authorization.refresh;

public final class RefreshTokenException extends RuntimeException {
    private final String code;

    public RefreshTokenException(String code) {
        super(code);
        this.code = code;
    }

    public RefreshTokenException(String code, Throwable cause) {
        super(code, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
