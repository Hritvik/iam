package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class IdentityEvidenceContractTest {
    @Test
    void v4DefinesClosedFactorRecoveryEvidenceAndLeastPrivilegeFunctions() throws Exception {
        try (var resource = getClass().getResourceAsStream(
                "/db/migration/V4__identity_factor_and_recovery_evidence.sql")) {
            assertThat(resource).isNotNull();
            var sql = new String(resource.readAllBytes(), StandardCharsets.UTF_8);
            assertThat(sql).contains("create table authentication_factor", "create table recovery_method",
                    "create function ensure_email_otp_factor", "create function ensure_verified_email_recovery",
                    "grant select on authentication_factor,recovery_method to iam_runtime");
            assertThat(sql).doesNotContain("grant insert", "grant update", "grant delete", "grant truncate");
        }
    }
}
