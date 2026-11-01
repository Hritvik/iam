package dev.distracted.iam.platform.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class ErrorEnvelopeContractTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void serializesOnlyStableSafeErrorFields() throws Exception {
        var envelope = ErrorEnvelope.of("invalid_request", "Request is invalid", "correlation-1");
        var json = objectMapper.readTree(objectMapper.writeValueAsBytes(envelope));

        assertThat(json.toString()).isEqualTo(
                "{\"error\":{\"code\":\"invalid_request\",\"message\":\"Request is invalid\","
                        + "\"correlationId\":\"correlation-1\"}}");
    }

    @Test
    void rejectsMalformedOrMissingFields() {
        for (var values : new String[][] {
            {null, "Safe", "correlation"},
            {"Invalid-Code", "Safe", "correlation"},
            {"invalid_request", null, "correlation"},
            {"invalid_request", " ", "correlation"},
            {"invalid_request", "Safe", null},
            {"invalid_request", "Safe", " "}
        }) {
            assertThatThrownBy(() -> ErrorEnvelope.of(values[0], values[1], values[2]))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        assertThatThrownBy(() -> new ErrorEnvelope(null))
                .isInstanceOf(NullPointerException.class);
    }
}

