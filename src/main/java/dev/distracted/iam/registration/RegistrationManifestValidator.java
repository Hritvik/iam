package dev.distracted.iam.registration;

public interface RegistrationManifestValidator {
    ValidatedRegistration validate(PinnedRegistrationDocument document);
}
