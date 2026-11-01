package dev.distracted.iam.activation;

public final class AppSubjectResolutionException extends RuntimeException {
    public AppSubjectResolutionException() { super("app_subject_resolution_failed"); }
}
