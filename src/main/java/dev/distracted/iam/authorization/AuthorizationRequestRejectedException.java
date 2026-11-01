package dev.distracted.iam.authorization;

public final class AuthorizationRequestRejectedException extends RuntimeException {
    public AuthorizationRequestRejectedException() { super("authorization_request_rejected"); }
}
