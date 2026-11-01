package dev.distracted.iam.platform.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.distracted.iam.bootstrap.IamApplication;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(
        classes = {
            IamApplication.class,
            CorrelationHttpTest.TestController.class,
            CorrelationHttpTest.TestSecurityConfiguration.class
        },
        properties = "spring.autoconfigure.exclude="
                + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration")
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class CorrelationHttpTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void echoesValidBoundedCorrelationIdInHeaderAndRequestContext() throws Exception {
        mockMvc.perform(get("/foundation-test/correlation")
                        .header("X-Correlation-Id", "request-123"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Correlation-Id", "request-123"))
                .andExpect(result -> assertThat(result.getResponse().getContentAsString())
                        .isEqualTo("request-123"));
    }

    @Test
    void generatesSafeCorrelationIdWhenInputIsMissingOrInvalid() throws Exception {
        for (String supplied : new String[] {"", "contains whitespace", "x".repeat(65)}) {
            var result = mockMvc.perform(get("/foundation-test/correlation")
                            .header("X-Correlation-Id", supplied))
                    .andExpect(status().isOk())
                    .andReturn();

            assertThat(result.getResponse().getHeader("X-Correlation-Id"))
                    .isNotEqualTo(supplied)
                    .matches("[a-f0-9]{32}");
        }

        var missing = mockMvc.perform(get("/foundation-test/correlation"))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(missing.getResponse().getHeader("X-Correlation-Id")).matches("[a-f0-9]{32}");
    }

    @Test
    void restoresPreexistingLoggingContextAfterRequest() throws Exception {
        MDC.put("correlationId", "outer-operation");
        try {
            mockMvc.perform(get("/foundation-test/correlation"))
                    .andExpect(status().isOk());
            assertThat(MDC.get("correlationId")).isEqualTo("outer-operation");
        } finally {
            MDC.remove("correlationId");
        }
    }

    @Test
    void unknownPlatformRouteUsesSafeCorrelatedErrorEnvelope() throws Exception {
        var result = mockMvc.perform(get("/foundation-test/not-found")
                        .header("X-Correlation-Id", "not-found-correlation"))
                .andExpect(status().isNotFound())
                .andExpect(header().string("X-Correlation-Id", "not-found-correlation"))
                .andExpect(jsonPath("$.error.code").value("not_found"))
                .andExpect(jsonPath("$.error.message").value("Resource not found"))
                .andExpect(jsonPath("$.error.correlationId").value("not-found-correlation"))
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .doesNotContain("exception", "stack", "SQL");
    }

    @Test
    void thrownPlatformExceptionUsesSafeCorrelatedErrorEnvelope(CapturedOutput output) throws Exception {
        var result = mockMvc.perform(get("/foundation-test/failure")
                        .header("X-Correlation-Id", "failure-correlation"))
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("X-Correlation-Id", "failure-correlation"))
                .andExpect(jsonPath("$.error.code").value("internal_error"))
                .andExpect(jsonPath("$.error.message").value("Request could not be completed"))
                .andExpect(jsonPath("$.error.correlationId").value("failure-correlation"))
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .doesNotContain("sensitive@example.invalid", "credential", "SQL", "RuntimeException");
        assertThat(output.getAll())
                .doesNotContain("sensitive@example.invalid", "credential", "SQL failure", "RuntimeException");
    }

    @RestController
    @PlatformEndpoint
    static class TestController {
        @GetMapping("/foundation-test/correlation")
        String correlation() {
            return MDC.get("correlationId");
        }

        @GetMapping("/foundation-test/failure")
        String failure() {
            throw new RuntimeException(
                    "SQL failure for sensitive@example.invalid with credential should never escape");
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class TestSecurityConfiguration {
        @Bean
        @Order(0)
        SecurityFilterChain foundationTestSecurityFilterChain(HttpSecurity http) throws Exception {
            return http.securityMatcher("/foundation-test/**")
                    .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                    .csrf(AbstractHttpConfigurer::disable)
                    .build();
        }
    }
}

