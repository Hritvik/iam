package dev.distracted.iam.authorization;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.authorization")
public record AuthorizationCodeCapabilityProperties(String codeDigestKeyReference) { }
