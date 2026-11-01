package dev.distracted.iam.identity;

@FunctionalInterface
public interface ChallengeDeliveryPort {
    void deliver(String challengeId, SecretChallengeCode code);
}
