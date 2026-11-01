package dev.distracted.iam.authorization;

public interface AuthorizationCodeRepository {
    AuthorizationIssueReceipt issue(AuthorizationCodeIssue issue);
}
