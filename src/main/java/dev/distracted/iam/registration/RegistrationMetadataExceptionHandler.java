package dev.distracted.iam.registration;

import dev.distracted.iam.platform.http.CorrelationIdFilter;
import dev.distracted.iam.platform.http.ErrorEnvelope;
import dev.distracted.iam.registration.web.RegistrationMetadataController;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = RegistrationMetadataController.class)
@ConditionalOnProperty(name = "iam.registration.dutch-development.enabled", havingValue = "true")
public final class RegistrationMetadataExceptionHandler {
    @ExceptionHandler(MetadataUnavailableException.class)
    ResponseEntity<ErrorEnvelope> unavailable() {
        var correlation = MDC.get(CorrelationIdFilter.MDC_KEY);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("Retry-After", "30")
                .body(ErrorEnvelope.of("metadata_unavailable", "Metadata is temporarily unavailable", correlation));
    }
}
