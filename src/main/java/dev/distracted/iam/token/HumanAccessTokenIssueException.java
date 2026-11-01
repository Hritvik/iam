package dev.distracted.iam.token;

public final class HumanAccessTokenIssueException extends RuntimeException {
    private final String reason;

    public HumanAccessTokenIssueException(String reason) {
        super("access token could not be issued");
        this.reason = reason;
    }

    public String reason() { return reason; }
}
