package dev.distracted.iam.messaging.relay;

public record RelayOutcome(int claimed, int published, int acknowledged, int quarantined) {
}
