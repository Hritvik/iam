package dev.distracted.iam.messaging.relay;

public record RelaySettings(String owner, int leaseSeconds, int batchLimit, int maximumAttempts) {
    public RelaySettings {
        if (owner == null || !owner.matches("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
                || leaseSeconds < 1 || leaseSeconds > 900
                || batchLimit < 1 || batchLimit > 1000
                || maximumAttempts < 1 || maximumAttempts > 100) {
            throw new IllegalArgumentException("relay_settings_invalid");
        }
    }
}
