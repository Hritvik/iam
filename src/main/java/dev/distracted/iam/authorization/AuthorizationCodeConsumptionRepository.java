package dev.distracted.iam.authorization;

import java.util.Optional;

public interface AuthorizationCodeConsumptionRepository {
    Optional<AuthorizationCodeProtection> findProtection(String codeId);
    Optional<ConsumedAuthorization> consume(AuthorizationCodeConsumption command);
}
