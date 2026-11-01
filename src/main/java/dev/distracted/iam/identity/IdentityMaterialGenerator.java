package dev.distracted.iam.identity;

public interface IdentityMaterialGenerator {
    String identityId();
    String identifierId();
    String challengeId();
    String auditId();
    String challengeCode();
}
