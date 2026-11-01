package dev.distracted.iam.token;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import tools.jackson.databind.ObjectMapper;

public final class JwksPublisher {
    private static final Pattern KEY_ID = Pattern.compile("^[A-Za-z0-9_-]{8,128}$");
    private final JwksDocument document;
    private final byte[] json;
    private final String etag;

    public JwksPublisher(AccessTokenSigningCapability capability) {
        this(capture(capability));
    }

    public JwksPublisher(AccessTokenSigningSnapshot snapshot) {
        try {
            validate(snapshot);
            var keys = snapshot.publicJwks().stream().sorted(java.util.Comparator.comparing(key -> key.getKeyID()))
                    .map(key -> {
                        var value = new LinkedHashMap<String, String>();
                        value.put("kty", "EC");
                        value.put("use", "sig");
                        value.put("alg", "ES256");
                        value.put("kid", key.getKeyID());
                        value.put("crv", "P-256");
                        value.put("x", key.getX().toString());
                        value.put("y", key.getY().toString());
                        return Map.copyOf(value);
                    }).toList();
            document = new JwksDocument(keys);
            json = new ObjectMapper().writeValueAsBytes(document);
            var digest = MessageDigest.getInstance("SHA-256").digest(json);
            etag = '"' + java.util.HexFormat.of().formatHex(digest) + '"';
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new HumanAccessTokenIssueException("signer_unavailable");
        }
    }

    public JwksDocument document() { return document; }
    public byte[] json() { return json.clone(); }
    public String etag() { return etag; }

    static AccessTokenSigningSnapshot capture(AccessTokenSigningCapability capability) {
        try {
            return java.util.Objects.requireNonNull(capability, "signing capability is required").snapshot();
        } catch (RuntimeException exception) {
            throw new HumanAccessTokenIssueException("signer_unavailable");
        }
    }

    private static void validate(AccessTokenSigningSnapshot snapshot) {
        if (snapshot == null || !"ACCESS_TOKEN_SIGNING".equals(snapshot.purpose())
                || !"ES256".equals(snapshot.algorithm()) || snapshot.activeKeyId() == null
                || !KEY_ID.matcher(snapshot.activeKeyId()).matches() || !snapshot.selfCheck()) {
            throw new HumanAccessTokenIssueException("signer_unavailable");
        }
        var keys = snapshot.publicJwks();
        if (keys == null || keys.isEmpty() || keys.size() > 8) {
            throw new HumanAccessTokenIssueException("signer_unavailable");
        }
        var ids = new java.util.HashSet<String>();
        var active = 0;
        for (var key : keys) {
            if (key == null || key.isPrivate() || !Curve.P_256.equals(key.getCurve())
                    || !KeyUse.SIGNATURE.equals(key.getKeyUse())
                    || !JWSAlgorithm.ES256.equals(key.getAlgorithm())
                    || key.getKeyID() == null || !KEY_ID.matcher(key.getKeyID()).matches()
                    || !ids.add(key.getKeyID())) throw new HumanAccessTokenIssueException("signer_unavailable");
            if (snapshot.activeKeyId().equals(key.getKeyID())) active++;
        }
        if (active != 1) throw new HumanAccessTokenIssueException("signer_unavailable");
        try {
            var input = "iam-access-token-signer-self-check-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            var signature = snapshot.sign(input);
            var activeKey = keys.stream().filter(key -> snapshot.activeKeyId().equals(key.getKeyID()))
                    .findFirst().orElseThrow();
            if (signature == null || signature.length != 64
                    || !new ECDSAVerifier(activeKey).verify(
                            new JWSHeader(JWSAlgorithm.ES256), input, Base64URL.encode(signature))) {
                throw new HumanAccessTokenIssueException("signer_unavailable");
            }
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new HumanAccessTokenIssueException("signer_unavailable");
        }
    }
}
