package dev.distracted.iam.activation;

import java.util.Objects;

public record AppSubjectResolution(AppSubject appSubject, Outcome outcome) {
    public enum Outcome { CREATED, EXISTING }

    public AppSubjectResolution {
        Objects.requireNonNull(appSubject, "app subject is required");
        Objects.requireNonNull(outcome, "outcome is required");
    }

    @Override public String toString() { return "AppSubjectResolution[outcome=" + outcome + "]"; }
}
