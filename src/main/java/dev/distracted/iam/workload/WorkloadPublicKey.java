package dev.distracted.iam.workload;

import com.nimbusds.jose.jwk.ECKey;

/** The public half of the workload signing key, published through the platform JWKS. */
public record WorkloadPublicKey(ECKey key) {
    public WorkloadPublicKey {
        if (key == null || key.isPrivate()) {
            throw new IllegalArgumentException("workload_public_key_invalid");
        }
    }
}
