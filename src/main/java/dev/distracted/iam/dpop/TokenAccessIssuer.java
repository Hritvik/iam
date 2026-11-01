package dev.distracted.iam.dpop;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import dev.distracted.iam.token.DpopKeyThumbprint;

@FunctionalInterface
public interface TokenAccessIssuer {
    String issue(ConsumedAuthorization authorization, AppSubject subject, int securityVersion,
                 DpopKeyThumbprint thumbprint, String correlationId, RegistrationManifest registration);
}
