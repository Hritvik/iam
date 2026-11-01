package dev.distracted.iam.identity.fixture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.distracted.iam.identity.SecretChallengeCode;
import dev.distracted.iam.platform.crypto.CapabilityMetadata;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.CapabilitySelfCheck;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.StartupCheckedCapability;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.TokenSignerCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.stream.Stream;

class FixtureSecurityBoundaryTest {
    @Test
    void receiptIsBoundedOneShotAndNonRevealing() {
        var receipt = new FixtureChallengeDelivery();
        var code = new SecretChallengeCode("code-canary");
        receipt.deliver("vch_abcdefghijklmnopqrstuv", code);
        assertThat(receipt.take("vch_abcdefghijklmnopqrstuv")).isEqualTo("code-canary");
        assertThat(receipt.toString()).doesNotContain("code-canary");
        assertThatThrownBy(() -> receipt.take("vch_abcdefghijklmnopqrstuv"))
                .isInstanceOf(FixtureException.class).hasMessage("fixture_receipt_unavailable");
        assertThatThrownBy(() -> receipt.deliver(null, code))
                .isInstanceOf(FixtureException.class).hasMessage("fixture_receipt_invalid");
        receipt.deliver("vch_abcdefghijklmnopqrstuv", code);
        assertThatThrownBy(() -> receipt.deliver("vch_abcdefghijklmnopqrstuv", code))
                .isInstanceOf(FixtureException.class).hasMessage("fixture_receipt_duplicate");
        receipt.clear();
        for (var index = 0; index < 8; index++) {
            receipt.deliver("vch_abcdefghijklmnopqrstuv" + index, code);
        }
        assertThatThrownBy(() -> receipt.deliver("vch_abcdefghijklmnopqrstuv9", code))
                .isInstanceOf(FixtureException.class).hasMessage("fixture_receipt_overflow");
        receipt.close();
    }

    @Test
    void capabilityGateRequiresHealthyPurposeBoundAlgorithms() {
        var encryption = healthy(StructuredIdentifierEncryptionCapability.class,
                CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", "fixture-encryption-key");
        var index = healthy(VersionedBlindIndexCapability.class,
                CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", "fixture-index-key");
        var digest = healthy(ChallengeDigestCapability.class,
                CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", "fixture-digest-key");
        var signer = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256",
                "fixture-signing-key");
        assertThat(new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest), List.of(signer)))
                .isNotNull();

        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(), List.of(index), List.of(digest), List.of(signer)))
                .isInstanceOf(FixtureException.class).hasMessage("fixture_encryption_unavailable");
        var wrongSigner = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "RS256",
                "fixture-signing-key");
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(wrongSigner))).isInstanceOf(FixtureException.class).hasMessage("fixture_signer_unhealthy");
        when(signer.selfCheck()).thenReturn(CapabilitySelfCheck.unhealthy("test_signer_unhealthy"));
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class).hasMessage("fixture_signer_unhealthy");
        when(signer.selfCheck()).thenThrow(new IllegalStateException("canary must be hidden"));
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class).hasMessage("fixture_signer_unhealthy")
                .hasNoCause();
    }

    @Test
    void capabilityGateRejectsEveryPairwiseKeyReferenceReuse() {
        for (var pair = 0; pair < 6; pair++) {
            var references = new String[] {"enc-key", "index-key", "digest-key", "sign-key"};
            var left = new int[] {0, 0, 0, 1, 1, 2}[pair];
            var right = new int[] {1, 2, 3, 2, 3, 3}[pair];
            references[right] = references[left];
            var encryption = healthy(StructuredIdentifierEncryptionCapability.class,
                    CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", references[0]);
            var index = healthy(VersionedBlindIndexCapability.class,
                    CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", references[1]);
            var digest = healthy(ChallengeDigestCapability.class,
                    CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", references[2]);
            var signer = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256",
                    references[3]);
            assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                    List.of(signer))).isInstanceOf(FixtureException.class)
                    .hasMessage("fixture_key_purpose_reuse").hasNoCause();
        }
    }

    @Test
    void capabilityGateRejectsHistoricalOverlapAndDuplicateReferencesWithinOnePurpose() {
        var encryption = healthy(StructuredIdentifierEncryptionCapability.class,
                CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", "enc-active");
        var index = healthy(VersionedBlindIndexCapability.class,
                CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", "index-active");
        var digest = healthy(ChallengeDigestCapability.class,
                CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", "digest-active");
        var signer = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256",
                "sign-active");
        when(encryption.keyReferences()).thenReturn(Map.of((short) 1, "enc-old", (short) 2, "shared-history"));
        when(index.keyReferences()).thenReturn(Map.of((short) 1, "index-old", (short) 2, "shared-history"));
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class).hasMessage("fixture_key_purpose_reuse");

        when(index.keyReferences()).thenReturn(Map.of((short) 1, "index-old", (short) 2, "index-active"));
        when(encryption.keyReferences()).thenReturn(Map.of((short) 1, "same-encryption", (short) 2, "same-encryption"));
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class).hasMessage("fixture_key_purpose_reuse");
    }

    @ParameterizedTest
    @MethodSource("cardinalityCases")
    void capabilityGateRejectsEveryMissingOrAmbiguousCapability(String target, boolean multiple) {
        var encryption = healthy(StructuredIdentifierEncryptionCapability.class,
                CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", "enc-key");
        var index = healthy(VersionedBlindIndexCapability.class,
                CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", "idx-key");
        var digest = healthy(ChallengeDigestCapability.class,
                CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", "dig-key");
        var signer = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", "sig-key");
        var encryptions = "encryption".equals(target) ? copies(encryption, multiple) : List.of(encryption);
        var indexes = "blind_index".equals(target) ? copies(index, multiple) : List.of(index);
        var digests = "digest".equals(target) ? copies(digest, multiple) : List.of(digest);
        var signers = "signer".equals(target) ? copies(signer, multiple) : List.of(signer);
        assertThatThrownBy(() -> new FixtureCapabilityGate(encryptions, indexes, digests, signers))
                .isInstanceOf(FixtureException.class).hasMessage("fixture_" + target + "_unavailable").hasNoCause();
    }

    @ParameterizedTest
    @MethodSource("healthCases")
    void capabilityGateRejectsEveryUnhealthyTypedCapability(String target, String fault) {
        var encryption = healthy(StructuredIdentifierEncryptionCapability.class,
                CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", "enc-key");
        var index = healthy(VersionedBlindIndexCapability.class,
                CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", "idx-key");
        var digest = healthy(ChallengeDigestCapability.class,
                CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", "dig-key");
        var signer = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", "sig-key");
        switch (target) {
            case "encryption" -> applyFault(encryption, CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", fault);
            case "blind_index" -> applyFault(index, CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", fault);
            case "digest" -> applyFault(digest, CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", fault);
            case "signer" -> applyFault(signer, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", fault);
            default -> throw new IllegalArgumentException("unknown_test_capability");
        }
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class)
                .hasMessage("fixture_" + target + "_unhealthy").hasNoCause();
    }

    @Test
    void capabilityGateRejectsMissingNullOrBlankVersionedReferenceCollections() {
        var encryption = healthy(StructuredIdentifierEncryptionCapability.class,
                CapabilityPurpose.IDENTIFIER_ENCRYPTION, "AES-256-GCM", "enc-key");
        var index = healthy(VersionedBlindIndexCapability.class,
                CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "HMAC-SHA-256", "idx-key");
        var digest = healthy(ChallengeDigestCapability.class,
                CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "HMAC-SHA-256", "dig-key");
        var signer = healthy(TokenSignerCapability.class, CapabilityPurpose.ACCESS_TOKEN_SIGNING, "ES256", "sig-key");
        for (var invalid : List.<Map<Short, String>>of(Map.of(), Map.of((short) 1, " "))) {
            when(encryption.keyReferences()).thenReturn(invalid);
            assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                    List.of(signer))).isInstanceOf(FixtureException.class)
                    .hasMessage("fixture_key_references_invalid").hasNoCause();
        }
        when(encryption.keyReferences()).thenReturn(null);
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class)
                .hasMessage("fixture_key_references_invalid").hasNoCause();
        var nullReference = new java.util.HashMap<Short, String>();
        nullReference.put((short) 1, null);
        when(encryption.keyReferences()).thenReturn(nullReference);
        assertThatThrownBy(() -> new FixtureCapabilityGate(List.of(encryption), List.of(index), List.of(digest),
                List.of(signer))).isInstanceOf(FixtureException.class)
                .hasMessage("fixture_key_references_invalid").hasNoCause();
    }

    private static Stream<Arguments> cardinalityCases() {
        return Stream.of("encryption", "blind_index", "digest", "signer")
                .flatMap(target -> Stream.of(Arguments.of(target, false), Arguments.of(target, true)));
    }

    private static Stream<Arguments> healthCases() {
        return Stream.of("encryption", "blind_index", "digest", "signer")
                .flatMap(target -> Stream.of("unhealthy", "wrong_purpose", "wrong_algorithm", "null_metadata",
                                "null_health", "self_check_throw")
                        .map(fault -> Arguments.of(target, fault)));
    }

    private static <T> List<T> copies(T value, boolean multiple) {
        return multiple ? List.of(value, value) : List.of();
    }

    private static void applyFault(StartupCheckedCapability capability, CapabilityPurpose purpose,
            String algorithm, String fault) {
        switch (fault) {
            case "unhealthy" -> when(capability.selfCheck()).thenReturn(CapabilitySelfCheck.unhealthy("test_unhealthy"));
            case "wrong_purpose" -> when(capability.metadata()).thenReturn(new CapabilityMetadata(
                    purpose == CapabilityPurpose.ACCESS_TOKEN_SIGNING ? CapabilityPurpose.IDENTIFIER_ENCRYPTION
                            : CapabilityPurpose.ACCESS_TOKEN_SIGNING,
                    "test-provider", "fault-key", algorithm));
            case "wrong_algorithm" -> when(capability.metadata()).thenReturn(new CapabilityMetadata(
                    purpose, "test-provider", "fault-key", "RS256"));
            case "null_metadata" -> when(capability.metadata()).thenReturn(null);
            case "null_health" -> when(capability.selfCheck()).thenReturn(null);
            case "self_check_throw" -> when(capability.selfCheck()).thenThrow(new IllegalStateException("hidden"));
            default -> throw new IllegalArgumentException("unknown_test_fault");
        }
    }

    private static <T extends StartupCheckedCapability> T healthy(Class<T> type, CapabilityPurpose purpose,
            String algorithm, String keyReference) {
        var capability = mock(type);
        when(capability.metadata()).thenReturn(new CapabilityMetadata(purpose, "test-provider", keyReference,
                algorithm));
        when(capability.selfCheck()).thenReturn(CapabilitySelfCheck.ready());
        if (capability instanceof StructuredIdentifierEncryptionCapability versioned) {
            when(versioned.keyReferences()).thenReturn(Map.of((short) 1, keyReference));
        } else if (capability instanceof VersionedBlindIndexCapability versioned) {
            when(versioned.keyReferences()).thenReturn(Map.of((short) 1, keyReference));
        } else if (capability instanceof ChallengeDigestCapability versioned) {
            when(versioned.keyReferences()).thenReturn(Map.of((short) 1, keyReference));
        }
        return capability;
    }
}
