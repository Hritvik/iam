package dev.distracted.iam.platform.http;

import java.util.Objects;
import java.util.regex.Pattern;

public record ErrorEnvelope(ErrorBody error) {
    public ErrorEnvelope {
        Objects.requireNonNull(error, "error");
    }

    public static ErrorEnvelope of(String code, String message, String correlationId) {
        return new ErrorEnvelope(new ErrorBody(code, message, correlationId));
    }

    public record ErrorBody(String code, String message, String correlationId) {
        private static final Pattern STABLE_CODE = Pattern.compile("[a-z][a-z0-9_]{0,63}");

        public ErrorBody {
            if (code == null || !STABLE_CODE.matcher(code).matches()) {
                throw new IllegalArgumentException("error code must be a stable machine code");
            }
            requireText(message, "message");
            requireText(correlationId, "correlationId");
        }

        private static void requireText(String value, String field) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(field + " must not be blank");
            }
        }
    }
}

