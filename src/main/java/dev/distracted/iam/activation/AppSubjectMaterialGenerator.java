package dev.distracted.iam.activation;

public interface AppSubjectMaterialGenerator {
    AppSubject nextSubject();

    String nextAuditId();
}
