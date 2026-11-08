package dev.distracted.iam.messaging.relay.transport;

import dev.distracted.iam.workload.WorkloadAccessTokenIssuer;
import java.util.Objects;

/**
 * Mints a fresh workload access token for every delivery attempt.
 *
 * <p>The consumer's ingestion route is mutating, and the profile requires a distinct {@code jti} per
 * mutation. The event id stays the idempotency key across retries; the credential does not.
 */
public final class SelfIssuedWorkloadTokenSupplier implements WorkloadTokenSupplier {
    private final WorkloadAccessTokenIssuer issuer;
    private final String workloadId;
    private final String audience;
    private final String scope;

    public SelfIssuedWorkloadTokenSupplier(
            WorkloadAccessTokenIssuer issuer,
            String workloadId,
            String audience,
            String scope) {
        this.issuer = Objects.requireNonNull(issuer);
        this.workloadId = Objects.requireNonNull(workloadId);
        this.audience = Objects.requireNonNull(audience);
        this.scope = Objects.requireNonNull(scope);
    }

    @Override
    public String token() {
        return issuer.issue(workloadId, audience, scope);
    }
}
