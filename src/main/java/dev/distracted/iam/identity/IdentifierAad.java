package dev.distracted.iam.identity;

import java.nio.charset.StandardCharsets;

public final class IdentifierAad {
    private IdentifierAad() { }

    public static byte[] forField(String environment, String table, String rowId, String field,
            IdentifierType type, short normalizationVersion, short encryptionKeyVersion) {
        return encode("iam-identifier-aad-v1", environment, table, rowId, field, type.wireValue(),
                Short.toString(normalizationVersion), Short.toString(encryptionKeyVersion));
    }

    private static byte[] encode(String... values) {
        var result = new StringBuilder();
        for (var value : values) {
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            result.append(bytes.length).append(':').append(value);
        }
        return result.toString().getBytes(StandardCharsets.UTF_8);
    }
}
