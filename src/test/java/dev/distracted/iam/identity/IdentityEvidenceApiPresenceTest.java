package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class IdentityEvidenceApiPresenceTest {
    @Test
    void exposesOnlyBoundedEnsureOperationsAndTypedResults() throws Exception {
        var service = Class.forName("dev.distracted.iam.identity.IdentityEvidenceService");
        assertThat(Arrays.stream(service.getMethods()).map(method -> method.getName()))
                .contains("ensureEmailOtpFactor", "ensureVerifiedEmailRecovery")
                .doesNotContain("markPrerequisitesSatisfied");
        var outcome = Class.forName("dev.distracted.iam.identity.EvidenceOutcome");
        assertThat(outcome.getEnumConstants()).extracting(Object::toString)
                .containsExactly("CREATED", "EXISTING", "REJECTED", "CONFLICT");
    }
}
