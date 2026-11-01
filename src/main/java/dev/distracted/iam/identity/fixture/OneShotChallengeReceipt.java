package dev.distracted.iam.identity.fixture;

interface OneShotChallengeReceipt {
    String take(String challengeId);

    void clear();
}
