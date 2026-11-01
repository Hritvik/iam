package dev.distracted.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.HashSet;
import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.authorization.ConsumedAuthorization;
import org.junit.jupiter.api.Test;

class TokenValueObjectTest {
    @Test void thumbprintRequiresCanonicalThirtyTwoByteBase64Url() {
        var valid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assertThat(new DpopKeyThumbprint(valid).value()).isEqualTo(valid);
        for (var invalid : new String[] {null, "", valid + "=", valid.substring(1),
                "__________________________________________-"}) {
            assertThatThrownBy(() -> new DpopKeyThumbprint(invalid))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("DPoP key thumbprint is invalid");
        }
        assertThat(new DpopKeyThumbprint(valid).toString()).doesNotContain(valid);
    }

    @Test void secureJtiMaterialHasAtLeastOneHundredFortyFourBitsAndDoesNotRepeat() {
        var generator = new SecureAccessTokenMaterialGenerator(new SecureRandom());
        var values = new HashSet<String>();
        for (var index = 0; index < 1_000; index++) {
            var value = generator.nextJti();
            assertThat(value).matches("^[A-Za-z0-9_-]{24}$");
            assertThat(values.add(value)).isTrue();
        }
    }

    @Test void compactTokenRequiresAThreeSegmentBoundedValueAndRendersRedacted() {
        var token = new SignedHumanAccessToken("a.b.c");
        assertThat(token.toString()).isEqualTo("SignedHumanAccessToken[redacted]");
        assertThatThrownBy(() -> new SignedHumanAccessToken("not-compact"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SignedHumanAccessToken("a." + "x".repeat(8_193) + ".c"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void issueCommandRejectsEveryMissingOrInvalidTrustedInput() throws Exception {
        var authorization = new ConsumedAuthorization("request", "dutch-development", "dutch-mobile", "dutch-api",
                "https://api.dutch.example", "hid_internal", "member:read", new byte[32], new byte[32]);
        var subject = new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        var thumbprint = new DpopKeyThumbprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assertThatThrownBy(() -> new HumanAccessTokenIssueCommand(null, subject, 1, thumbprint, "correlation"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssueCommand(authorization, null, 1, thumbprint, "correlation"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssueCommand(authorization, subject, 1, null, "correlation"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssueCommand(authorization, subject, 0, thumbprint, "correlation"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssueCommand(authorization, subject, 1, thumbprint, ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenIssueCommand(authorization, subject, 1, thumbprint, null))
                .isInstanceOf(IllegalArgumentException.class);
        var command = new HumanAccessTokenIssueCommand(authorization, subject, 9, thumbprint, "correlation-canary");
        assertThat(command.toString()).doesNotContain("hid_internal", subject.value(), thumbprint.value(),
                "correlation-canary");
        assertThat(new tools.jackson.databind.ObjectMapper().writeValueAsString(command))
                .doesNotContain("hid_internal", subject.value(), thumbprint.value(), "correlation-canary")
                .isEqualTo("{}");
    }
}
