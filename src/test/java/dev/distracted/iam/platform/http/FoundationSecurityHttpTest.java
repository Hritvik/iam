package dev.distracted.iam.platform.http;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.distracted.iam.bootstrap.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(
        classes = {IamApplication.class, FoundationSecurityHttpTest.TestController.class},
        properties = "spring.autoconfigure.exclude="
                + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration")
@AutoConfigureMockMvc
class FoundationSecurityHttpTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void unauthenticatedRequestGetsSafeCorrelatedEnvelope() throws Exception {
        mockMvc.perform(get("/foundation-security-test")
                        .header("X-Correlation-Id", "unauthenticated-correlation"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Correlation-Id", "unauthenticated-correlation"))
                .andExpect(jsonPath("$.error.code").value("authentication_required"))
                .andExpect(jsonPath("$.error.message").value("Authentication is required"))
                .andExpect(jsonPath("$.error.correlationId").value("unauthenticated-correlation"));
    }

    @Test
    void authenticatedRequestGetsSafeCorrelatedDeniedEnvelope() throws Exception {
        mockMvc.perform(get("/foundation-security-test")
                        .with(user("test-user"))
                        .header("X-Correlation-Id", "denied-correlation"))
                .andExpect(status().isForbidden())
                .andExpect(header().string("X-Correlation-Id", "denied-correlation"))
                .andExpect(jsonPath("$.error.code").value("access_denied"))
                .andExpect(jsonPath("$.error.message").value("Access is denied"))
                .andExpect(jsonPath("$.error.correlationId").value("denied-correlation"));
    }

    @RestController
    @PlatformEndpoint
    static class TestController {
        @GetMapping("/foundation-security-test")
        String shouldNeverRun() {
            return "unreachable";
        }
    }
}

