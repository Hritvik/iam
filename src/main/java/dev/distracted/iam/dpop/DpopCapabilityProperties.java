package dev.distracted.iam.dpop;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.dpop")
public record DpopCapabilityProperties(boolean enabled, String stateDigestKeyReference) { }
