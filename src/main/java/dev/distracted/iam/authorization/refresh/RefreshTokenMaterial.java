package dev.distracted.iam.authorization.refresh;

import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Pattern;

/** One refresh family and its first token, produced by the material generator. */
public record RefreshTokenMaterial(String familyId, String tokenId, String rawToken, byte[] digest) {
    private static final Pattern FAMILY_ID = Pattern.compile("^rfm_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern TOKEN_ID = Pattern.compile("^rft_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern RAW_TOKEN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    public RefreshTokenMaterial {
        if (familyId == null || !FAMILY_ID.matcher(familyId).matches()
                || tokenId == null || !TOKEN_ID.matcher(tokenId).matches()
                || rawToken == null || !RAW_TOKEN.matcher(rawToken).matches()
                || digest == null || digest.length != 32) {
            throw new IllegalArgumentException("refresh_material_invalid");
        }
        digest = digest.clone();
    }

    @Override
    public byte[] digest() {
        return digest.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RefreshTokenMaterial material
                && familyId.equals(material.familyId) && tokenId.equals(material.tokenId)
                && rawToken.equals(material.rawToken) && Arrays.equals(digest, material.digest);
    }

    @Override
    public int hashCode() {
        return Objects.hash(familyId, tokenId, rawToken, Arrays.hashCode(digest));
    }

    @Override
    public String toString() {
        return "RefreshTokenMaterial[familyId=" + familyId + ",tokenId=" + tokenId + ",redacted]";
    }
}
