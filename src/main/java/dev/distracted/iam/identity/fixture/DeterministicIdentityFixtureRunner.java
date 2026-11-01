package dev.distracted.iam.identity.fixture;

import dev.distracted.iam.identity.EvidenceOutcome;
import dev.distracted.iam.identity.IdentifierType;
import dev.distracted.iam.identity.IdentityEvidenceService;
import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.identity.IdentityService;
import dev.distracted.iam.identity.VerificationResult;
import dev.distracted.iam.messaging.CorrelationId;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import org.springframework.beans.factory.SmartInitializingSingleton;

final class DeterministicIdentityFixtureRunner implements SmartInitializingSingleton {
    private static final String IDENTIFIER = String.join("", "portfolio-primary@", "iam-fixture.invalid");
    private final IdentityService identities;
    private final IdentityEvidenceService evidence;
    private final OneShotChallengeReceipt receipts;
    private final SecureRandom random = new SecureRandom();

    DeterministicIdentityFixtureRunner(IdentityService identities, IdentityEvidenceService evidence,
            OneShotChallengeReceipt receipts) {
        this.identities = identities;
        this.evidence = evidence;
        this.receipts = receipts;
    }

    @Override
    public void afterSingletonsInstantiated() { establish(); }

    IdentityReference establish() {
        try {
            var correlation = correlation();
            var identity = identities.find(IdentifierType.EMAIL, IDENTIFIER).orElseGet(() -> verifyNew(correlation));
            var factor = evidence.ensureEmailOtpFactor(identity, evidence.currentIdentityVersion(identity), correlation);
            requireSuccess(factor.outcome());
            var recovery = evidence.ensureVerifiedEmailRecovery(identity, factor.identityVersion(), correlation);
            requireSuccess(recovery.outcome());
            return identity;
        } catch (RuntimeException exception) {
            receipts.clear();
            if (exception instanceof FixtureException fixture) throw fixture;
            throw new FixtureException("fixture_setup_failed");
        }
    }

    private IdentityReference verifyNew(CorrelationId correlation) {
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, IDENTIFIER,
                Duration.ofMinutes(10), 3, correlation);
        var result = identities.verify(challenge, receipts.take(challenge), correlation);
        if (result == VerificationResult.VERIFIED) return identity;
        if (result == VerificationResult.CONFLICT) {
            return identities.find(IdentifierType.EMAIL, IDENTIFIER)
                    .orElseThrow(() -> new FixtureException("fixture_identity_conflict"));
        }
        throw new FixtureException("fixture_verification_rejected");
    }

    private static void requireSuccess(EvidenceOutcome outcome) {
        if (outcome != EvidenceOutcome.CREATED && outcome != EvidenceOutcome.EXISTING) {
            throw new FixtureException("fixture_evidence_rejected");
        }
    }

    private CorrelationId correlation() {
        var bytes = new byte[18];
        random.nextBytes(bytes);
        return new CorrelationId("cor_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    @Override public String toString() { return "DeterministicIdentityFixtureRunner[portfolio-primary]"; }
}
