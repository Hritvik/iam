package dev.distracted.iam.identity.fixture;

import dev.distracted.iam.identity.ChallengeDeliveryPort;
import dev.distracted.iam.identity.SecretChallengeCode;
import java.util.LinkedHashMap;
import java.util.Map;

final class FixtureChallengeDelivery implements ChallengeDeliveryPort, OneShotChallengeReceipt, AutoCloseable {
    private static final int CAPACITY = 8;
    private final Map<String, String> receipts = new LinkedHashMap<>();

    @Override
    public synchronized void deliver(String challengeId, SecretChallengeCode code) {
        if (challengeId == null || code == null) throw new FixtureException("fixture_receipt_invalid");
        if (receipts.containsKey(challengeId)) throw new FixtureException("fixture_receipt_duplicate");
        if (receipts.size() >= CAPACITY) throw new FixtureException("fixture_receipt_overflow");
        receipts.put(challengeId, code.reveal());
    }

    @Override
    public synchronized String take(String challengeId) {
        var code = receipts.remove(challengeId);
        if (code == null) throw new FixtureException("fixture_receipt_unavailable");
        return code;
    }

    @Override
    public synchronized void clear() {
        receipts.clear();
    }

    @Override
    public void close() {
        clear();
    }

    @Override
    public String toString() {
        return "FixtureChallengeDelivery[protected]";
    }
}
