package dev.distracted.iam.token;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonIgnore;

public record HumanAccessTokenIssueCommand(
        @JsonIgnore ConsumedAuthorization authorization,
        @JsonIgnore RegistrationManifest registration,
        @JsonIgnore AppSubject appSubject,
        @JsonIgnore int securityVersion,
        @JsonIgnore DpopKeyThumbprint dpopKeyThumbprint,
        @JsonIgnore String correlationId) {
    public HumanAccessTokenIssueCommand(ConsumedAuthorization authorization, AppSubject appSubject, int securityVersion,
                                        DpopKeyThumbprint dpopKeyThumbprint, String correlationId) {
        this(authorization, null, appSubject, securityVersion, dpopKeyThumbprint, correlationId);
    }

    public HumanAccessTokenIssueCommand {
        Objects.requireNonNull(authorization, "authorization is required");
        Objects.requireNonNull(appSubject, "app subject is required");
        Objects.requireNonNull(dpopKeyThumbprint, "DPoP key thumbprint is required");
        if (registration != null && (!registration.appRegistrationId().equals(authorization.appRegistrationId())
                || !registration.client().clientId().equals(authorization.clientId())
                || !registration.resource().resourceId().equals(authorization.resourceId()))) {
            throw new IllegalArgumentException("registration does not match authorization");
        }
        if (securityVersion < 1) throw new IllegalArgumentException("security version is invalid");
        if (correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("correlation ID is invalid");
        }
    }

    @Override public String toString() {
        return "HumanAccessTokenIssueCommand[securityVersion=" + securityVersion + ",redacted]";
    }
}
