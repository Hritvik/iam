package dev.distracted.iam.messaging.snapshot;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class SnapshotValueObjectTest {
    @Test void pageRejectsOversizedOrIncoherentContent() {
        var item = new OnboardingSnapshotItem("aps_0123456789012345678901ab", "act_012345678901234567",
                "ACTIVE", 2, "FIRST_ACTIVATION", 1, "PROFILE_REQUIRED");
        assertThatThrownBy(() -> new OnboardingSnapshotPage(null, List.of(item), null, false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingSnapshotPage("dutch-development", null, null, false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingSnapshotPage("dutch-development",
                java.util.Collections.nCopies(201, item), null, false))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
