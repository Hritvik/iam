package dev.distracted.iam.token.web;

import dev.distracted.iam.token.JwksPublisher;
import dev.distracted.iam.platform.http.PlatformEndpoint;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PlatformEndpoint
@ConditionalOnExpression("${iam.token.enabled:false} or ${iam.workload.enabled:false}")
public final class JwksController {
    private final JwksPublisher publisher;

    public JwksController(JwksPublisher publisher) { this.publisher = publisher; }

    @RequestMapping(path = "/oauth2/jwks", method = {RequestMethod.GET, RequestMethod.HEAD},
            produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<byte[]> jwks(HttpServletRequest request) {
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setCacheControl("public, max-age=300, must-revalidate");
        headers.setETag(publisher.etag());
        headers.set("X-Content-Type-Options", "nosniff");
        if (publisher.etag().equals(request.getHeader(HttpHeaders.IF_NONE_MATCH))) {
            return new ResponseEntity<>(null, headers, HttpStatus.NOT_MODIFIED);
        }
        var body = RequestMethod.HEAD.name().equals(request.getMethod()) ? null : publisher.json();
        return new ResponseEntity<>(body, headers, HttpStatus.OK);
    }
}
