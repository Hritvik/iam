package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Test;

class FixtureReceiptPresenceTest {
    @Test
    void fixtureReceiptIsInternalAndNotAProductionIdentityPort() throws Exception {
        var receipt = Class.forName("dev.distracted.iam.identity.fixture.OneShotChallengeReceipt");
        assertThat(Modifier.isPublic(receipt.getModifiers())).isFalse();
        assertThat(ChallengeDeliveryPort.class.isAssignableFrom(receipt)).isFalse();
    }
}
