package dev.distracted.iam.token;

import dev.distracted.iam.activation.AppSubject;

public interface AppSubjectBindingVerifier {
    boolean belongsTo(String humanIdentityId, String appRegistrationId, AppSubject appSubject);
}
