package dev.distracted.iam.dpop;

import dev.distracted.iam.activation.AppSubjectResolution;
import dev.distracted.iam.authorization.ConsumedAuthorization;

@FunctionalInterface
public interface TokenSubjectResolver {
    AppSubjectResolution resolve(ConsumedAuthorization authorization, String correlationId);
}
