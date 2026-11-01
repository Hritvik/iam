package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.platform.crypto.AesGcmIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.HmacBlindIndexCapability;
import dev.distracted.iam.platform.crypto.HmacChallengeDigestCapability;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IdentifierCryptographyTest {
    private static final byte[] KEY = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f"
            + "101112131415161718191a1b1c1d1e1f");

    @Test
    void blindIndexUsesExactPurposeSeparatedGrammar() {
        var capability = new HmacBlindIndexCapability("test-key", (short) 7, KEY);
        var index = capability.derive("test", IdentifierType.EMAIL, (short) 1, "A@example.com");
        assertThat(HexFormat.of().formatHex(index)).isEqualTo(
                "dd7f79a0acbbffe1d6e17b2b893cd45faee29048a6dd9b8facee3ae94757a0f1");
        assertThat(capability.derive("development", IdentifierType.EMAIL, (short) 1, "A@example.com"))
                .isNotEqualTo(index);
    }

    @Test
    void challengeDigestBindsChallengeAndDoesNotReuseBlindIndexGrammar() {
        var capability = new HmacChallengeDigestCapability("test-digest", (short) 3, KEY);
        var digest = capability.digest("test", "vch_abcdefghijklmnopqrstuv", "secret-code");
        assertThat(HexFormat.of().formatHex(digest)).isEqualTo(
                "0fc052aca57f4701aad6b6e5feeaf134f5f22719b3b23f2782c15e2f3c9581c5");
        assertThat(capability.digest("test", "vch_abcdefghijklmnopqrstuw", "secret-code"))
                .isNotEqualTo(digest);
    }

    @Test
    void encryptionSeparatesFieldsRowsAndReturnsDefensiveBytes() {
        var crypto = new AesGcmIdentifierEncryptionCapability("test-encryption", (short) 2, KEY);
        var canonicalAad = IdentifierAad.forField("test", "verification_challenge",
                "vch_abcdefghijklmnopqrstuv", "canonical", IdentifierType.EMAIL, (short) 1, (short) 2);
        var displayAad = IdentifierAad.forField("test", "verification_challenge",
                "vch_abcdefghijklmnopqrstuv", "display", IdentifierType.EMAIL, (short) 1, (short) 2);
        var first = crypto.seal("A@example.com".getBytes(StandardCharsets.UTF_8), canonicalAad);
        var second = crypto.seal("A@example.com".getBytes(StandardCharsets.UTF_8), canonicalAad);
        assertThat(first.nonce()).hasSize(12).isNotEqualTo(second.nonce());
        assertThat(first.tag()).hasSize(16);
        assertThat(crypto.open(first, canonicalAad)).asString(StandardCharsets.UTF_8).isEqualTo("A@example.com");
        assertThatThrownBy(() -> crypto.open(first, displayAad))
                .isInstanceOf(IdentifierCryptoException.class)
                .hasMessage("identifier_crypto_failed")
                .hasNoCause()
                .hasMessageNotContaining("A@example.com");
        var copy = first.ciphertext();
        copy[0] ^= 1;
        assertThat(first.ciphertext()).isNotEqualTo(copy);
        assertThat(first.toString()).doesNotContain("ciphertext", "nonce", "tag");
        var packed = crypto.encrypt("A@example.com".getBytes(StandardCharsets.UTF_8), canonicalAad);
        assertThat(crypto.decrypt(packed, canonicalAad)).asString(StandardCharsets.UTF_8).isEqualTo("A@example.com");
        assertThatThrownBy(() -> crypto.decrypt(new byte[10], canonicalAad))
                .isInstanceOf(IdentifierCryptoException.class).hasNoCause();
    }

    @Test
    void rejectsInvalidKeyAndSealedValueShapesWithoutLeakingBytes() {
        assertThatThrownBy(() -> new AesGcmIdentifierEncryptionCapability("ref", (short) 1, new byte[16]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacBlindIndexCapability("ref", (short) 0, KEY))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacChallengeDigestCapability("ref", (short) 1, new byte[8]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new dev.distracted.iam.platform.crypto.SealedIdentifierValue(
                new byte[0], new byte[12], new byte[16], (short) 1)).hasMessage("ciphertext_invalid");
        assertThatThrownBy(() -> new dev.distracted.iam.platform.crypto.SealedIdentifierValue(
                new byte[1], new byte[11], new byte[16], (short) 1)).hasMessage("nonce_invalid");
        assertThatThrownBy(() -> new dev.distracted.iam.platform.crypto.SealedIdentifierValue(
                new byte[1], new byte[12], new byte[15], (short) 1)).hasMessage("tag_invalid");
        assertThatThrownBy(() -> new dev.distracted.iam.platform.crypto.SealedIdentifierValue(
                new byte[1], new byte[12], new byte[16], (short) 0)).hasMessage("key_version_invalid");
        assertThatThrownBy(() -> new HmacBlindIndexCapability("ref", (short) 1, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void keyringsReadOldAndWriteOnlyTheActiveVersion() {
        var secondKey = KEY.clone();
        secondKey[0] ^= 0x55;
        var oldEncryption = new AesGcmIdentifierEncryptionCapability("enc-old", (short) 1, KEY);
        var aadOne = IdentifierAad.forField("test", "verification_challenge", "vch_abcdefghijklmnopqrstuv",
                "canonical", IdentifierType.EMAIL, (short) 1, (short) 1);
        var oldValue = oldEncryption.seal("value".getBytes(StandardCharsets.UTF_8), aadOne);
        var rotatedEncryption = new AesGcmIdentifierEncryptionCapability(
                Map.of((short) 1, "enc-old", (short) 2, "enc-new"), (short) 2,
                Map.of((short) 1, KEY, (short) 2, secondKey));
        assertThat(rotatedEncryption.open(oldValue, aadOne)).asString(StandardCharsets.UTF_8).isEqualTo("value");
        var aadTwo = IdentifierAad.forField("test", "verification_challenge", "vch_abcdefghijklmnopqrstuv",
                "canonical", IdentifierType.EMAIL, (short) 1, (short) 2);
        assertThat(rotatedEncryption.seal("new".getBytes(StandardCharsets.UTF_8), aadTwo).keyVersion()).isEqualTo((short) 2);

        var rotatedIndexes = new HmacBlindIndexCapability(
                Map.of((short) 1, "idx-old", (short) 2, "idx-new"), (short) 2,
                Map.of((short) 1, KEY, (short) 2, secondKey));
        assertThat(rotatedIndexes.deriveReadable("test", IdentifierType.EMAIL, (short) 1, "A@example.com"))
                .containsOnlyKeys((short) 1, (short) 2);
        assertThat(rotatedIndexes.keyVersion()).isEqualTo((short) 2);

        var rotatedDigests = new HmacChallengeDigestCapability(
                Map.of((short) 1, "dig-old", (short) 2, "dig-new"), (short) 2,
                Map.of((short) 1, KEY, (short) 2, secondKey));
        assertThat(rotatedDigests.digest((short) 1, "test", "vch_abcdefghijklmnopqrstuv", "code"))
                .isEqualTo(new HmacChallengeDigestCapability("dig-old", (short) 1, KEY)
                        .digest("test", "vch_abcdefghijklmnopqrstuv", "code"));
        assertThat(rotatedDigests.keyReferences().values()).doesNotHaveDuplicates();
    }

    @Test
    void rejectsIncompleteOrUnsafeKeyrings() {
        var references = Map.of((short) 1, "one");
        assertThatThrownBy(() -> new AesGcmIdentifierEncryptionCapability(null, (short) 1, Map.of()))
                .hasMessage("encryption_keyring_invalid");
        assertThatThrownBy(() -> new AesGcmIdentifierEncryptionCapability(references, (short) 2,
                Map.of((short) 1, KEY))).hasMessage("encryption_keyring_invalid");
        assertThatThrownBy(() -> new AesGcmIdentifierEncryptionCapability(references, (short) 1,
                Map.of((short) 2, KEY))).hasMessage("encryption_keyring_invalid");
        assertThatThrownBy(() -> new HmacBlindIndexCapability(references, (short) 2,
                Map.of((short) 1, KEY))).hasMessage("blind_index_keyring_invalid");
        assertThatThrownBy(() -> new HmacBlindIndexCapability(references, (short) 1,
                Map.of((short) 1, new byte[8]))).hasMessage("blind_index_keyring_invalid");
        assertThatThrownBy(() -> new HmacChallengeDigestCapability(references, (short) 2,
                Map.of((short) 1, KEY))).hasMessage("challenge_digest_keyring_invalid");
        assertThatThrownBy(() -> new HmacChallengeDigestCapability(references, (short) 1,
                Map.of((short) 1, new byte[8]))).hasMessage("challenge_digest_keyring_invalid");
        var digests = new HmacChallengeDigestCapability("one", (short) 1, KEY);
        assertThatThrownBy(() -> digests.digest((short) 2, "test", "vch_abcdefghijklmnopqrstuv", "code"))
                .hasMessage("challenge_digest_failed").hasNoCause();
    }
}
