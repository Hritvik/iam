package dev.distracted.iam.dpop;

import dev.distracted.iam.authorization.AuthorizationCodeRedemptionCommand;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import java.util.Optional;

@FunctionalInterface
public interface TokenAuthorizationRedeemer {
    Optional<ConsumedAuthorization> redeem(AuthorizationCodeRedemptionCommand command);
}
