package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class IdentifierNormalizerTest {
    private final IdentifierNormalizer normalizer = new IdentifierNormalizer();

    @ParameterizedTest
    @MethodSource("validIdentifiers")
    void normalizesVersionOneExactly(IdentifierType type, String input, String canonical, String display) {
        var normalized = normalizer.normalize(type, input);
        assertThat(normalized.canonical()).isEqualTo(canonical);
        assertThat(normalized.display()).isEqualTo(display);
        assertThat(normalized.normalizationVersion()).isEqualTo((short) 1);
        assertThat(normalizer.normalize(type, normalized.canonical()).canonical()).isEqualTo(canonical);
    }

    static Stream<Arguments> validIdentifiers() {
        return Stream.of(
                Arguments.of(IdentifierType.EMAIL, "\tLocal+tag@BÜCHER.Example\r\n",
                        "Local+tag@xn--bcher-kva.example", "Local+tag@BÜCHER.Example"),
                Arguments.of(IdentifierType.EMAIL, "A.B@example.COM", "A.B@example.com", "A.B@example.COM"),
                Arguments.of(IdentifierType.PHONE, " +919876543210 ", "+919876543210", "+919876543210"),
                Arguments.of(IdentifierType.PHONE, "+12", "+12", "+12"));
    }

    @ParameterizedTest
    @MethodSource("invalidIdentifiers")
    void rejectsInvalidWithoutEchoingTheValue(IdentifierType type, String input) {
        assertThatThrownBy(() -> normalizer.normalize(type, input))
                .isInstanceOf(IdentifierInvalidException.class)
                .hasMessage("identifier_invalid")
                .hasMessageNotContaining(input);
    }

    static Stream<Arguments> invalidIdentifiers() {
        return Stream.of(
                Arguments.of(IdentifierType.EMAIL, "a@@example.com"),
                Arguments.of(IdentifierType.EMAIL, "\"a\"@example.com"),
                Arguments.of(IdentifierType.EMAIL, "ü@example.com"),
                Arguments.of(IdentifierType.EMAIL, "a..b@example.com"),
                Arguments.of(IdentifierType.EMAIL, "a@example.com."),
                Arguments.of(IdentifierType.EMAIL, "a@exa mple.com"),
                Arguments.of(IdentifierType.EMAIL, "a@\u200D.example"),
                Arguments.of(IdentifierType.EMAIL, "\u00a0a@example.com\u00a0"),
                Arguments.of(IdentifierType.PHONE, "+1"),
                Arguments.of(IdentifierType.PHONE, "+012"),
                Arguments.of(IdentifierType.PHONE, "+1 23"),
                Arguments.of(IdentifierType.PHONE, "00123"),
                Arguments.of(IdentifierType.PHONE, "+１２３"),
                Arguments.of(IdentifierType.PHONE, "+1234567890123456"));
    }

    @Test
    void enforcesEmailOctetBounds() {
        assertThatThrownBy(() -> normalizer.normalize(IdentifierType.EMAIL,
                "a".repeat(65) + "@example.com")).isInstanceOf(IdentifierInvalidException.class);
        assertThatThrownBy(() -> normalizer.normalize(IdentifierType.EMAIL,
                "a@" + "b".repeat(64) + ".com")).isInstanceOf(IdentifierInvalidException.class);
    }

    @Test
    void rejectsMissingTypeValueAndUnsupportedNormalizationRecord() {
        assertThatThrownBy(() -> normalizer.normalize(null, "a@example.com"))
                .isInstanceOf(IdentifierInvalidException.class);
        assertThatThrownBy(() -> normalizer.normalize(IdentifierType.EMAIL, null))
                .isInstanceOf(IdentifierInvalidException.class);
        assertThatThrownBy(() -> new NormalizedIdentifier(IdentifierType.EMAIL, (short) 2,
                "a@example.com", "a@example.com")).hasMessage("normalization_version_invalid");
        assertThatThrownBy(() -> new NormalizedIdentifier(null, (short) 1,
                "a@example.com", "a@example.com")).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> normalizer.normalize(IdentifierType.EMAIL, "a".repeat(1025)))
                .isInstanceOf(IdentifierInvalidException.class);
        assertThatThrownBy(() -> normalizer.normalize(IdentifierType.EMAIL, "界".repeat(700)))
                .isInstanceOf(IdentifierInvalidException.class);
    }
}
