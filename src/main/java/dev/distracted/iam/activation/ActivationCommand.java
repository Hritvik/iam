package dev.distracted.iam.activation;

public record ActivationCommand(String activationId, String appRegistrationId, String humanIdentityId,
                                String appSubject, long expectedVersion, String correlationId) {
}
