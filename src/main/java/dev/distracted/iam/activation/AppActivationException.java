package dev.distracted.iam.activation;

public final class AppActivationException extends RuntimeException {
    public AppActivationException() { super("app_activation_unavailable"); }
    public AppActivationException(Throwable cause) { super("app_activation_unavailable", cause); }
}
