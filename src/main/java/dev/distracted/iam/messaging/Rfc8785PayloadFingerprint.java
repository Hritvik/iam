package dev.distracted.iam.messaging;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.erdtman.jcs.JsonCanonicalizer;

public final class Rfc8785PayloadFingerprint implements PayloadFingerprint {
    @Override
    public String fingerprint(EventPayload payload) {
        try {
            var canonical = new JsonCanonicalizer(payload.canonicalizationInput()).getEncodedUTF8();
            var digest = MessageDigest.getInstance("SHA-256").digest(canonical);
            return java.util.HexFormat.of().formatHex(digest);
        } catch (IOException exception) {
            throw new IllegalArgumentException("payload is not valid JSON", exception);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
