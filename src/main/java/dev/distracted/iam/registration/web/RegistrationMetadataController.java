package dev.distracted.iam.registration.web;

import dev.distracted.iam.platform.http.PlatformEndpoint;
import dev.distracted.iam.registration.AuthorizationServerMetadata;
import dev.distracted.iam.registration.ProtectedResourceMetadata;
import dev.distracted.iam.registration.RegistrationMetadata;
import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PlatformEndpoint
@ConditionalOnProperty(name = "iam.registration.dutch-development.enabled", havingValue = "true")
public final class RegistrationMetadataController {
    private final RegistrationMetadata metadata;

    public RegistrationMetadataController(RegistrationMetadata metadata) { this.metadata = metadata; }

    @GetMapping(value = "/.well-known/oauth-authorization-server", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<AuthorizationServerMetadata> authorizationServer() { return response(metadata.authorizationServer()); }

    @GetMapping(value = "/.well-known/oauth-protected-resource", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<ProtectedResourceMetadata> protectedResource() { return response(metadata.protectedResource()); }

    @RequestMapping(value = "/.well-known/oauth-authorization-server", method = RequestMethod.HEAD)
    ResponseEntity<Void> authorizationServerHead() {
        metadata.authorizationServer();
        return headResponse();
    }

    @RequestMapping(value = "/.well-known/oauth-protected-resource", method = RequestMethod.HEAD)
    ResponseEntity<Void> protectedResourceHead() {
        metadata.protectedResource();
        return headResponse();
    }

    private static <T> ResponseEntity<T> response(T value) {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofSeconds(300)).cachePublic())
                .header("X-Content-Type-Options", "nosniff").body(value);
    }

    private static ResponseEntity<Void> headResponse() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofSeconds(300)).cachePublic())
                .header("X-Content-Type-Options", "nosniff").contentType(MediaType.APPLICATION_JSON).build();
    }
}
