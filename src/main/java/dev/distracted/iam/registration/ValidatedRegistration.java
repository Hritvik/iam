package dev.distracted.iam.registration;

public record ValidatedRegistration(RegistrationManifest manifest, String fingerprint) { }
