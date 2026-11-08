package dev.distracted.iam.platform.crypto;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Signs with an ES256 (P-256, SHA-256, JWS raw R||S) private key supplied as PKCS#8 material.
 *
 * <p>The key is injected from secret storage; this class never reads or writes key files.
 */
public final class JcaEs256TokenSignerCapability implements TokenSignerCapability {
    private static final String ALGORITHM = "ES256";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSAinP1363Format";
    private static final int SIGNATURE_BYTES = 64;
    private static final byte[] SELF_CHECK_INPUT = "iam-token-signer-self-check".getBytes(StandardCharsets.UTF_8);

    private final CapabilityMetadata metadata;
    private final PrivateKey signingKey;

    public JcaEs256TokenSignerCapability(String provider, String keyReference, String algorithm, byte[] pkcs8) {
        if (!ALGORITHM.equals(algorithm)) {
            throw new IllegalArgumentException("signer_algorithm_invalid");
        }
        if (pkcs8 == null || pkcs8.length == 0) {
            throw new IllegalArgumentException("signer_key_missing");
        }
        this.metadata = new CapabilityMetadata(
                CapabilityPurpose.ACCESS_TOKEN_SIGNING, provider, keyReference, ALGORITHM);
        this.signingKey = parseKey(pkcs8);
    }

    private static PrivateKey parseKey(byte[] pkcs8) {
        try {
            var key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8.clone()));
            if (!(key instanceof ECPrivateKey ecKey) || !isP256(ecKey.getParams())) {
                throw new IllegalArgumentException("signer_key_not_p256");
            }
            return key;
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("signer_key_invalid", exception);
        }
    }

    private static boolean isP256(ECParameterSpec actual) throws GeneralSecurityException {
        var parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(actual);
        var curveName = parameters.getParameterSpec(ECGenParameterSpec.class).getName();
        parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return curveName.equals(parameters.getParameterSpec(ECGenParameterSpec.class).getName());
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        try {
            var signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(signingKey);
            signature.update(signingInput.clone());
            var signed = signature.sign();
            if (signed.length != SIGNATURE_BYTES) {
                throw new IllegalStateException("signer_output_invalid");
            }
            return signed;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("token_signing_failed", exception);
        }
    }

    @Override
    public CapabilityMetadata metadata() {
        return metadata;
    }

    @Override
    public CapabilitySelfCheck selfCheck() {
        try {
            sign(SELF_CHECK_INPUT);
            return CapabilitySelfCheck.ready();
        } catch (RuntimeException exception) {
            return CapabilitySelfCheck.unhealthy("signer_unavailable");
        }
    }
}
