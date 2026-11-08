package dev.distracted.iam.workload;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import java.net.URI;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

final class WorkloadKeys {
    static final Pattern KEY_ID = Pattern.compile("^[A-Za-z0-9_-]{8,128}$");
    private static final Pattern WORKLOAD_ID = Pattern.compile("^wl_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern APP_ID = Pattern.compile("^[a-z][a-z0-9-]{2,63}$");
    private static final Pattern CLIENT_ID = Pattern.compile("^[a-z][a-z0-9-]{2,63}$");

    private WorkloadKeys() {
    }

    static ECKey signingKey(WorkloadIdentityProperties.Signing signing) {
        var keyId = required(signing.keyId(), "workload_signing_key_id_missing");
        if (!KEY_ID.matcher(keyId).matches()) {
            throw new WorkloadAccessTokenException("workload_signing_key_id_invalid");
        }
        try {
            var publicKey = (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(decode(signing.publicKey())));
            var signingMaterial = (ECPrivateKey) KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(decode(signing.privateKey())));
            return new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(signingMaterial)
                    .keyID(keyId)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .build();
        } catch (WorkloadAccessTokenException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new WorkloadAccessTokenException("workload_signing_key_invalid", exception);
        }
    }

    static ECKey trustedKey(WorkloadIdentityProperties.TrustedKey trusted) {
        var keyId = required(trusted.keyId(), "workload_trust_key_id_missing");
        if (!KEY_ID.matcher(keyId).matches()) {
            throw new WorkloadAccessTokenException("workload_trust_key_id_invalid");
        }
        try {
            var publicKey = (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(decode(trusted.publicKey())));
            return new ECKey.Builder(Curve.P_256, publicKey)
                    .keyID(keyId)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .build();
        } catch (WorkloadAccessTokenException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new WorkloadAccessTokenException("workload_trust_key_invalid", exception);
        }
    }

    static String requireHttpsIssuer(String value) {
        try {
            var uri = URI.create(required(value, "workload_issuer_missing"));
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.getPath().isEmpty()) {
                throw new IllegalArgumentException();
            }
            return value;
        } catch (RuntimeException exception) {
            throw new WorkloadAccessTokenException("workload_issuer_invalid");
        }
    }

    static String required(String value, String code) {
        if (value == null || value.isBlank()) {
            throw new WorkloadAccessTokenException(code);
        }
        return value;
    }

    static void requireWorkloadId(String value) {
        if (value == null || !WORKLOAD_ID.matcher(value).matches()) {
            throw new WorkloadAccessTokenException("workload_id_invalid");
        }
    }

    static void requireAppId(String value, String code) {
        if (value == null || !APP_ID.matcher(value).matches()) {
            throw new WorkloadAccessTokenException(code);
        }
    }

    static void requireClientId(String value, String code) {
        if (value == null || !CLIENT_ID.matcher(value).matches()) {
            throw new WorkloadAccessTokenException(code);
        }
    }

    private static byte[] decode(String value) {
        try {
            return Base64.getDecoder().decode(required(value, "workload_key_material_missing"));
        } catch (IllegalArgumentException exception) {
            throw new WorkloadAccessTokenException("workload_key_material_invalid", exception);
        }
    }
}
