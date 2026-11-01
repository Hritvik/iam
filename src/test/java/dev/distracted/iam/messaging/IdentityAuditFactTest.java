package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class IdentityAuditFactTest {
    @ParameterizedTest
    @MethodSource("lifecycleFacts")
    void acceptsOnlyClosedPiiFreeLifecycleFacts(String fact, String kind, String prefix) {
        var value = new AuditFact("aud_abcdefghijklmnop", fact, kind, prefix + "abcdefghijklmnopqrstuv",
                "SUCCEEDED", new CorrelationId("cor_abcdefghijklmnop"), null, null, null, Instant.EPOCH);
        assertThat(value.eventId()).isNull();
    }

    static Stream<Arguments> lifecycleFacts() {
        return Stream.of(
                Arguments.of("IDENTITY_CREATED", "IDENTITY", "hid_"),
                Arguments.of("IDENTIFIER_CHALLENGE_ISSUED", "VERIFICATION_CHALLENGE", "vch_"),
                Arguments.of("IDENTIFIER_CHALLENGE_SUPERSEDED", "VERIFICATION_CHALLENGE", "vch_"),
                Arguments.of("IDENTIFIER_CHALLENGE_LOCKED", "VERIFICATION_CHALLENGE", "vch_"),
                Arguments.of("IDENTIFIER_VERIFIED", "VERIFIED_IDENTIFIER", "vid_"));
    }

    @ParameterizedTest
    @MethodSource("invalidFacts")
    void rejectsOpenOrMismatchedFacts(String fact, String kind, String subject) {
        assertThatThrownBy(() -> new AuditFact("aud_abcdefghijklmnop", fact, kind, subject, "SUCCEEDED",
                new CorrelationId("cor_abcdefghijklmnop"), null, null, null, Instant.EPOCH))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("audit identity is invalid");
    }

    static Stream<Arguments> invalidFacts() {
        return Stream.of(
                Arguments.of("IDENTITY_CREATED", "VERIFICATION_CHALLENGE", "vch_abcdefghijklmnopqrstuv"),
                Arguments.of("IDENTIFIER_VERIFIED", "VERIFIED_IDENTIFIER", "email@example.invalid"),
                Arguments.of("UNKNOWN", "IDENTITY", "hid_abcdefghijklmnopqrstuv"));
    }
}
