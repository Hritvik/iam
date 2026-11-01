package dev.distracted.iam.identity;
public final class ChallengeRejectedException extends IllegalArgumentException {
    public ChallengeRejectedException() { super("challenge_rejected"); }
}
