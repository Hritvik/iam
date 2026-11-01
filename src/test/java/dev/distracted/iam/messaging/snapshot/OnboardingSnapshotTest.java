package dev.distracted.iam.messaging.snapshot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class OnboardingSnapshotTest {
    private static final String SUBJECT = "aps_0123456789012345678901ab";

    @Test void cursorIsOpaqueAndRejectsMalformedValues() {
        var cursor = new SnapshotCursor();
        var encoded = cursor.encode(SUBJECT);
        assertThat(encoded).doesNotContain(SUBJECT).matches("^[A-Za-z0-9_-]+$");
        assertThat(cursor.decode(encoded)).isEqualTo(SUBJECT);
        assertThatThrownBy(() -> cursor.decode("not-a-cursor!")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> cursor.decode("")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> cursor.decode("eA")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> cursor.encode("aps_short")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void theItemSerializesWithExactlyTheAllowlistedKeys() throws Exception {
        var item = new OnboardingSnapshotItem("aps_0123456789012345678901ab", "act_012345678901234567",
                "ACTIVE", 2, "FIRST_ACTIVATION", 1, "PROFILE_REQUIRED");
        var json = new tools.jackson.databind.ObjectMapper().writeValueAsString(item);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> value = new tools.jackson.databind.ObjectMapper().readValue(json,
                java.util.Map.class);
        assertThat(value).containsOnlyKeys("appSubject", "activationId", "activationState", "activationVersion",
                "onboardingReason", "onboardingVersion", "requiredProfileState");
        assertThat(json).doesNotContain("hid_", "identity", "token");
    }

    @Test void pageCoherenceRequiresACursorExactlyWhenMoreRemain() {
        var item = new OnboardingSnapshotItem(SUBJECT, "act_012345678901234567", "ACTIVE", 2,
                "FIRST_ACTIVATION", 1, "PROFILE_REQUIRED");
        assertThatThrownBy(() -> new OnboardingSnapshotPage("dutch-development", List.of(item), null, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingSnapshotPage("dutch-development", List.of(item), "abc", false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(new OnboardingSnapshotPage("dutch-development", List.of(item), null, false).hasMore()).isFalse();
    }
}
