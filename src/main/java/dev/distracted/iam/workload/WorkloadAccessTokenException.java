package dev.distracted.iam.workload;

public final class WorkloadAccessTokenException extends RuntimeException {
    private final String code;

    public WorkloadAccessTokenException(String code) {
        super(code);
        this.code = code;
    }

    public WorkloadAccessTokenException(String code, Throwable cause) {
        super(code, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
