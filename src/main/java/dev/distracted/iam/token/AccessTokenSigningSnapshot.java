package dev.distracted.iam.token;

import com.nimbusds.jose.jwk.ECKey;
import java.util.List;
import java.util.Objects;

public record AccessTokenSigningSnapshot(
        String purpose,
        String algorithm,
        String activeKeyId,
        List<ECKey> publicJwks,
        boolean selfCheck,
        SigningOperation signingOperation) {
    public AccessTokenSigningSnapshot {
        publicJwks = publicJwks == null ? null : List.copyOf(publicJwks);
        signingOperation = Objects.requireNonNull(signingOperation, "signing operation is required");
    }

    public byte[] sign(byte[] signingInput) {
        return signingOperation.sign(signingInput.clone()).clone();
    }

    @FunctionalInterface
    public interface SigningOperation {
        byte[] sign(byte[] signingInput);
    }
}
