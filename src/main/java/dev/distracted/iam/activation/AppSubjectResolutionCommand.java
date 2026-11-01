package dev.distracted.iam.activation;

import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.messaging.CorrelationId;
import java.util.regex.Pattern;

public record AppSubjectResolutionCommand(
        String appRegistrationId, IdentityReference identity, CorrelationId correlationId) {
    private static final Pattern APP_ID = Pattern.compile("^[a-z][a-z0-9-]{2,63}$");
    private static final Pattern IDENTITY_ID = Pattern.compile("^hid_[A-Za-z0-9_-]{22,128}$");

    public AppSubjectResolutionCommand {
        if (appRegistrationId == null || !APP_ID.matcher(appRegistrationId).matches()
                || identity == null || identity.identityId() == null
                || !IDENTITY_ID.matcher(identity.identityId()).matches() || correlationId == null) {
            throw new IllegalArgumentException("app subject resolution command is invalid");
        }
    }

    @Override public String toString() { return "AppSubjectResolutionCommand[redacted]"; }
}
