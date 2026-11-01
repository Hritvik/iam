package dev.distracted.iam.registration;

public interface RegistrationMetadata {
    AuthorizationServerMetadata authorizationServer();
    ProtectedResourceMetadata protectedResource();
}
