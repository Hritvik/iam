package dev.distracted.iam.activation;

public interface AppSubjectRepository {
    enum Outcome { CREATED, EXISTING, RETRY_COLLISION, REJECTED }

    record Result(Outcome outcome, AppSubject appSubject) { }

    Result resolve(String appId, String identityId, AppSubject candidate, String auditId, String correlationId);
}
