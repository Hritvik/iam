package dev.distracted.iam.platform.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(annotations = PlatformEndpoint.class)
public class PlatformEndpointExceptionHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(PlatformEndpointExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorEnvelope> unexpectedFailure() {
        var correlationId = correlationId();
        LOGGER.error("Platform request failed; correlationId={}", correlationId);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorEnvelope.of(
                        "internal_error",
                        "Request could not be completed",
                        correlationId));
    }

    private static String correlationId() {
        return CorrelationIdFilter.acceptedOrGenerated(MDC.get(CorrelationIdFilter.MDC_KEY));
    }
}

