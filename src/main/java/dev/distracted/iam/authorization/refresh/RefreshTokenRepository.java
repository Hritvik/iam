package dev.distracted.iam.authorization.refresh;

import java.util.Optional;

public interface RefreshTokenRepository {
    Optional<RefreshFamilyView> findByTokenDigest(byte[] tokenDigest);

    RefreshIssueReceipt issue(RefreshFamilyIssue issue);

    RefreshRotationResult rotate(RefreshRotationCommand command);

    boolean revokeFamily(String familyId, String reason, String correlationId);
}
