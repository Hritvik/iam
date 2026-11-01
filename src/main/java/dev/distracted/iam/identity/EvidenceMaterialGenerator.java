package dev.distracted.iam.identity;

public interface EvidenceMaterialGenerator {
    String factorId();

    String recoveryMethodId();

    String auditId();
}
