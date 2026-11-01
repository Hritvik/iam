package dev.distracted.iam.messaging.snapshot.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotItem;
import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotPage;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class OnboardingSnapshotHttpTest {
    private static final String APP = "dutch-development";
    private static final WorkloadAuthenticator BOUND = request -> Optional.of(new WorkloadPrincipal(APP,
            Set.of("iam:onboarding:read"), "https://iam.distracted.invalid/internal/onboarding"));

    private static MockMvc mvc(dev.distracted.iam.messaging.snapshot.OnboardingSnapshotQuery query,
                               WorkloadAuthenticator authenticator) {
        return MockMvcBuilders.standaloneSetup(new OnboardingSnapshotController(query, authenticator)).build();
    }

    @Test void servesTheBoundedPageOnTheContractedRoute() throws Exception {
        var mvc = mvc((app, cursor, limit) -> new OnboardingSnapshotPage(app,
                List.of(new OnboardingSnapshotItem("aps_0123456789012345678901ab", "act_012345678901234567",
                        "ACTIVE", 2, "FIRST_ACTIVATION", 1, "PROFILE_REQUIRED")), null, false), BOUND);

        mvc.perform(get("/internal/v1/apps/{app}/onboarding", APP).param("limit", "10")
                        .header("X-Correlation-ID", "cor_0123456789012345"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Correlation-ID", "cor_0123456789012345"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Pragma", "no-cache"))
                .andExpect(jsonPath("$.data.appRegistrationId").value(APP))
                .andExpect(jsonPath("$.data.hasMore").value(false))
                .andExpect(jsonPath("$.data.items[0].activationState").value("ACTIVE"))
                .andExpect(jsonPath("$.data.nextCursor").doesNotExist());
    }

    @Test void mismatchMissingScopeWrongAudienceAndAnonymousLookNotFound() throws Exception {
        var rejecting = mvc((app, cursor, limit) -> {
            throw new AssertionError("must not query");
        }, BOUND);
        rejecting.perform(get("/internal/v1/apps/{app}/onboarding", "dutch-staging")
                        .header("X-Correlation-ID", "cor_0123456789012345"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.message").value("Resource was not found"))
                .andExpect(header().string("Cache-Control", "no-store"));

        mvc((app, cursor, limit) -> {
            throw new AssertionError("must not query");
        }, request -> Optional.of(new WorkloadPrincipal(APP, Set.of(),
                "https://iam.distracted.invalid/internal/onboarding")))
                .perform(get("/internal/v1/apps/{app}/onboarding", APP))
                .andExpect(status().isNotFound());

        mvc((app, cursor, limit) -> {
            throw new AssertionError("must not query");
        }, request -> Optional.of(new WorkloadPrincipal(APP, Set.of("iam:onboarding:read"), "other")))
                .perform(get("/internal/v1/apps/{app}/onboarding", APP))
                .andExpect(status().isNotFound());

        mvc((app, cursor, limit) -> {
            throw new AssertionError("must not query");
        }, request -> Optional.empty())
                .perform(get("/internal/v1/apps/{app}/onboarding", APP))
                .andExpect(status().isNotFound());
    }

    @Test void malformedCursorOutOfRangeLimitAndDatabaseFailureUseClosedEnvelopes() throws Exception {
        var invalid = mvc((app, cursor, limit) -> {
            throw new IllegalArgumentException("snapshot_cursor_invalid");
        }, BOUND);
        invalid.perform(get("/internal/v1/apps/{app}/onboarding", APP).param("cursor", "bad!"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("invalid_request"));
        invalid.perform(get("/internal/v1/apps/{app}/onboarding", APP).param("limit", "201"))
                .andExpect(status().isBadRequest());
        invalid.perform(get("/internal/v1/apps/{app}/onboarding", APP).param("limit", "abc"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("invalid_request"));

        mvc((app, cursor, limit) -> {
            throw new IllegalStateException("onboarding_snapshot_unavailable");
        }, BOUND).perform(get("/internal/v1/apps/{app}/onboarding", APP))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error.code").value("internal_error"))
                .andExpect(jsonPath("$.error.message").value("Request could not be completed"))
                .andExpect(jsonPath("$.error.correlationId").isNotEmpty());
    }

    @Test void invalidCorrelationIsReplacedAndThePayloadOmitsANullCursor() throws Exception {
        var mvc = mvc((app, cursor, limit) -> new OnboardingSnapshotPage(app, List.of(), null, false), BOUND);
        var result = mvc.perform(get("/internal/v1/apps/{app}/onboarding", APP)
                        .header("X-Correlation-ID", "bad correlation!"))
                .andExpect(status().isOk()).andReturn();

        assertThat(result.getResponse().getHeader("X-Correlation-ID")).matches("^cor_[A-Za-z0-9_-]{16,128}$");
        var json = result.getResponse().getContentAsString();
        assertThat(json).doesNotContain("nextCursor").doesNotContain("hid_").doesNotContain("identity")
                .doesNotContain("token");
    }
}
