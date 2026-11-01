package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.messaging.CorrelationId;
import dev.distracted.iam.platform.crypto.AesGcmIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.HmacBlindIndexCapability;
import dev.distracted.iam.platform.crypto.HmacChallengeDigestCapability;
import dev.distracted.iam.platform.persistence.JdbcAuditFactRepository;
import dev.distracted.iam.platform.persistence.SpringTransactionRunner;
import java.sql.DriverManager;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

@Testcontainers
class IdentityPersistenceIntegrationTest {
    @Container private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.0-alpine");
    private static final String RUNTIME_CREDENTIAL = UUID.randomUUID().toString();
    private static JdbcTemplate jdbc;
    private static JdbcTemplate owner;
    private CapturingDelivery delivery;
    private IdentityService identities;

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_CREDENTIAL + "' in role iam_runtime");
            statement.execute("grant usage,create on schema public to iam_migrator");
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()).load().migrate();
        var source = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_CREDENTIAL);
        jdbc = new JdbcTemplate(source);
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    @BeforeEach
    void setUp() {
        owner.execute("truncate table app_subject,verified_identifier_blind_index,verified_identifier,verification_challenge,"
                + "human_identity,audit_fact restart identity cascade");
        delivery = new CapturingDelivery();
        var encryptionKey = key(1);
        var indexKey = key(2);
        var digestKey = key(3);
        var source = ((org.springframework.jdbc.datasource.DriverManagerDataSource) jdbc.getDataSource());
        identities = new IdentityService(jdbc,
                new SpringTransactionRunner(new TransactionTemplate(new DataSourceTransactionManager(source))),
                new JdbcAuditFactRepository(jdbc), new IdentifierNormalizer(),
                new AesGcmIdentifierEncryptionCapability("test-encryption", (short) 1, encryptionKey),
                new HmacBlindIndexCapability("test-index", (short) 1, indexKey),
                new HmacChallengeDigestCapability("test-digest", (short) 1, digestKey),
                new SequentialMaterials(), delivery, "test");
    }

    @Test
    void createsIssuesConsumesFindsAndNeverPublishesOutbox() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, " Person+tag@BÜCHER.Example ",
                Duration.ofMinutes(10), 3, correlation);
        assertThat(delivery.challengeIds).containsExactly(challenge);
        assertThat(identities.verify(challenge, delivery.codes.getFirst(), correlation)).isEqualTo(VerificationResult.VERIFIED);
        assertThat(identities.verify(challenge, delivery.codes.getFirst(), correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.find(IdentifierType.EMAIL, "Person+tag@xn--bcher-kva.example"))
                .contains(identity);
        assertThat(jdbc.queryForObject("select security_version from human_identity where identity_id=?", Long.class,
                identity.identityId())).isEqualTo(2L);
        assertThat(jdbc.queryForObject("select count(*) from verified_identifier", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from outbox_event", Integer.class)).isZero();
        assertThat(owner.queryForObject("select string_agg(encode(canonical_ciphertext,'hex'),'') from verified_identifier",
                String.class)).doesNotContain("506572736f6e");
    }

    @Test
    void wrongAttemptsLockAndTerminalChallengeCannotBeConsumed() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.PHONE, "+919876543210",
                Duration.ofMinutes(5), 2, correlation);
        assertThat(identities.verify(challenge, "wrong-one", correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.verify(challenge, "wrong-two", correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.verify(challenge, delivery.codes.getFirst(), correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(jdbc.queryForMap("select state,attempt_count from verification_challenge where challenge_id=?", challenge))
                .containsEntry("state", "LOCKED").containsEntry("attempt_count", 2);
    }

    @Test
    void resendSupersedesAndUsesFreshCodeDigestAndNonce() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var first = identities.issue(identity.identityId(), IdentifierType.EMAIL, "A@example.com",
                Duration.ofMinutes(5), 3, correlation);
        var second = identities.resend(first, "A@example.com", Duration.ofMinutes(5), 3, correlation);
        assertThat(second).isNotEqualTo(first);
        assertThat(delivery.codes).hasSize(2).doesNotHaveDuplicates();
        assertThat(identities.verify(first, delivery.codes.getFirst(), correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.verify(second, delivery.codes.getLast(), correlation)).isEqualTo(VerificationResult.VERIFIED);
        assertThat(jdbc.queryForObject("select count(*) from verification_challenge where identity_id=? and state='ISSUED'",
                Integer.class, identity.identityId())).isZero();
    }

    @Test
    void expirationUsesDatabaseClockAtBoundary() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, "expiry@example.com",
                Duration.ofMinutes(5), 3, correlation);
        owner.update("update verification_challenge set created_at=transaction_timestamp()-interval '2 minutes',"
                + "expires_at=transaction_timestamp() where challenge_id=?", challenge);
        assertThat(identities.verify(challenge, delivery.codes.getFirst(), correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(jdbc.queryForObject("select state from verification_challenge where challenge_id=?", String.class, challenge))
                .isEqualTo("EXPIRED");
    }

    @Test
    void duplicateCanonicalIdentifierRollsBackLoserAndConcurrentConsumeHasOneEffect() throws Exception {
        var correlation = correlation();
        var one = identities.createIdentity(correlation);
        var two = identities.createIdentity(correlation);
        var first = identities.issue(one.identityId(), IdentifierType.EMAIL, "A@BÜCHER.example", Duration.ofMinutes(5), 3, correlation);
        var second = identities.issue(two.identityId(), IdentifierType.EMAIL, "A@xn--bcher-kva.EXAMPLE", Duration.ofMinutes(5), 3, correlation);
        var firstCode = delivery.codes.get(0);
        var secondCode = delivery.codes.get(1);
        assertThat(identities.verify(first, firstCode, correlation)).isEqualTo(VerificationResult.VERIFIED);
        assertThat(identities.verify(second, secondCode, correlation)).isEqualTo(VerificationResult.CONFLICT);
        assertThat(jdbc.queryForObject("select state from verification_challenge where challenge_id=?", String.class, second))
                .isEqualTo("ISSUED");

        var thirdIdentity = identities.createIdentity(correlation);
        var third = identities.issue(thirdIdentity.identityId(), IdentifierType.EMAIL, "race@example.com",
                Duration.ofMinutes(5), 3, correlation);
        var code = delivery.codes.getLast();
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var a = executor.submit(() -> {
                start.await();
                return identities.verify(third, code, correlation);
            });
            var b = executor.submit(() -> {
                start.await();
                return identities.verify(third, code, correlation);
            });
            start.countDown();
            assertThat(List.of(a.get(), b.get())).containsExactlyInAnyOrder(
                    VerificationResult.VERIFIED, VerificationResult.REJECTED);
        }
        assertThat(jdbc.queryForObject("select count(*) from verified_identifier where identity_id=?", Integer.class,
                thirdIdentity.identityId())).isEqualTo(1);
    }

    @Test
    void boundedPoliciesAndNonEnumeratingRejectionsAreEnforced() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        assertThatThrownBy(() -> identities.issue(identity.identityId(), IdentifierType.EMAIL, "x@example.com",
                Duration.ofSeconds(59), 3, correlation)).hasMessage("challenge_policy_invalid");
        assertThatThrownBy(() -> identities.issue(identity.identityId(), IdentifierType.EMAIL, "x@example.com",
                Duration.ofHours(25), 3, correlation)).hasMessage("challenge_policy_invalid");
        assertThatThrownBy(() -> identities.issue(identity.identityId(), IdentifierType.EMAIL, "x@example.com",
                Duration.ofMinutes(5), 21, correlation)).hasMessage("challenge_policy_invalid");
        assertThat(identities.find(IdentifierType.EMAIL, "absent@example.com")).isEmpty();
        assertThat(identities.verify("vch_abcdefghijklmnopqrstuv", null, correlation))
                .isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.verify("vch_abcdefghijklmnopqrstuv", "unknown", correlation))
                .isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.verify("invalid", "unknown", correlation)).isEqualTo(VerificationResult.REJECTED);
        assertThat(identities.verify("vch_abcdefghijklmnopqrstuv", "x".repeat(513), correlation))
                .isEqualTo(VerificationResult.REJECTED);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, "x@example.com",
                Duration.ofMinutes(5), 3, correlation);
        assertThatThrownBy(() -> identities.resend(challenge, "other@example.com", Duration.ofMinutes(5), 3, correlation))
                .isInstanceOf(ChallengeRejectedException.class).hasMessage("challenge_rejected");
        assertThat(identities.verify(challenge, delivery.codes.getLast(), correlation)).isEqualTo(VerificationResult.VERIFIED);
        assertThatThrownBy(() -> identities.issue(identity.identityId(), IdentifierType.EMAIL, "second@example.com",
                Duration.ofMinutes(5), 3, correlation)).isInstanceOf(ChallengeRejectedException.class);
    }

    @Test
    void rotationReadsOldChallengesAndIdentifiersWhileWritingNewVersions() {
        var correlation = correlation();
        var oldDelivery = new CapturingDelivery();
        var oldService = service(oldDelivery,
                new AesGcmIdentifierEncryptionCapability("enc-1", (short) 1, key(11)),
                new HmacBlindIndexCapability("idx-1", (short) 1, key(12)),
                new HmacChallengeDigestCapability("dig-1", (short) 1, key(13)));
        var oldIdentity = oldService.createIdentity(correlation);
        var oldChallenge = oldService.issue(oldIdentity.identityId(), IdentifierType.EMAIL, "old@example.com",
                Duration.ofMinutes(5), 3, correlation);
        var resendIdentity = oldService.createIdentity(correlation);
        var oldResend = oldService.issue(resendIdentity.identityId(), IdentifierType.EMAIL, "resend@example.com",
                Duration.ofMinutes(5), 3, correlation);

        var rotatedDelivery = new CapturingDelivery();
        var rotated = service(rotatedDelivery,
                new AesGcmIdentifierEncryptionCapability(Map.of((short) 1, "enc-1", (short) 2, "enc-2"),
                        (short) 2, Map.of((short) 1, key(11), (short) 2, key(21))),
                new HmacBlindIndexCapability(Map.of((short) 1, "idx-1", (short) 2, "idx-2"),
                        (short) 2, java.util.Set.of((short) 1, (short) 2),
                        Map.of((short) 1, key(12), (short) 2, key(22))),
                new HmacChallengeDigestCapability(Map.of((short) 1, "dig-1", (short) 2, "dig-2"),
                        (short) 2, Map.of((short) 1, key(13), (short) 2, key(23))));
        assertThat(rotated.verify(oldChallenge, oldDelivery.codes.getFirst(), correlation))
                .isEqualTo(VerificationResult.VERIFIED);
        assertThat(rotated.find(IdentifierType.EMAIL, "old@example.com")).contains(oldIdentity);
        var replacement = rotated.resend(oldResend, "resend@example.com", Duration.ofMinutes(5), 3, correlation);
        assertThat(rotated.verify(replacement, rotatedDelivery.codes.getFirst(), correlation))
                .isEqualTo(VerificationResult.VERIFIED);
        assertThat(jdbc.queryForMap("select encryption_key_version,candidate_blind_index_key_version,digest_key_version "
                + "from verification_challenge where challenge_id=?", replacement))
                .containsEntry("encryption_key_version", 2)
                .containsEntry("candidate_blind_index_key_version", 2)
                .containsEntry("digest_key_version", 2);
        var newIdentity = rotated.createIdentity(correlation);
        var newChallenge = rotated.issue(newIdentity.identityId(), IdentifierType.PHONE, "+14155552671",
                Duration.ofMinutes(5), 3, correlation);
        assertThat(rotated.verify(newChallenge, rotatedDelivery.codes.getLast(), correlation))
                .isEqualTo(VerificationResult.VERIFIED);
        assertThat(jdbc.queryForMap("select encryption_key_version,digest_key_version from verification_challenge "
                + "where challenge_id=?", newChallenge)).containsEntry("encryption_key_version", 2)
                .containsEntry("digest_key_version", 2);
        assertThat(jdbc.queryForList("select blind_index_key_version from verified_identifier_blind_index b "
                + "join verified_identifier v using(identifier_id) where v.identity_id=?", Integer.class,
                newIdentity.identityId())).contains(2);
        assertThat(jdbc.queryForList("select blind_index_key_version from verified_identifier_blind_index b "
                + "join verified_identifier v using(identifier_id) where v.identity_id=? order by 1", Integer.class,
                oldIdentity.identityId())).containsExactly(1, 2);
        var retiredOld = service(new CapturingDelivery(),
                new AesGcmIdentifierEncryptionCapability("enc-2", (short) 2, key(21)),
                new HmacBlindIndexCapability("idx-2", (short) 2, key(22)),
                new HmacChallengeDigestCapability("dig-2", (short) 2, key(23)));
        assertThat(retiredOld.find(IdentifierType.EMAIL, "old@example.com")).contains(oldIdentity);
    }

    @Test
    void runtimeCannotBypassVersionedStateTransitions() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, "grant@example.com",
                Duration.ofMinutes(5), 3, correlation);
        assertThatThrownBy(() -> jdbc.update(
                "update verification_challenge set state='CONSUMED' where challenge_id=?", challenge))
                .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> owner.update("update verification_challenge set attempt_count=max_attempts "
                + "where challenge_id=?", challenge)).rootCause().hasMessageContaining("violates check constraint");
    }

    @Test
    void concurrentIssueIsBoundedAndLeavesOneIssuedChallenge() throws Exception {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> issueOutcome(start, identity, "race-one@example.com", correlation));
            var second = executor.submit(() -> issueOutcome(start, identity, "race-two@example.com", correlation));
            start.countDown();
            assertThat(List.of(first.get(), second.get())).containsExactlyInAnyOrder("ISSUED", "CONFLICT");
        }
        assertThat(jdbc.queryForObject("select count(*) from verification_challenge where identity_id=? "
                + "and identifier_type='EMAIL' and state='ISSUED'", Integer.class, identity.identityId())).isEqualTo(1);
    }

    @Test
    void concurrentDuplicatePromotionHasOneWinnerAndNoPartialLoser() throws Exception {
        var correlation = correlation();
        var firstIdentity = identities.createIdentity(correlation);
        var secondIdentity = identities.createIdentity(correlation);
        var first = identities.issue(firstIdentity.identityId(), IdentifierType.PHONE, "+14155550999",
                Duration.ofMinutes(5), 3, correlation);
        var firstCode = delivery.codes.getLast();
        var second = identities.issue(secondIdentity.identityId(), IdentifierType.PHONE, "+14155550999",
                Duration.ofMinutes(5), 3, correlation);
        var secondCode = delivery.codes.getLast();
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var one = executor.submit(() -> verifyAfter(start, first, firstCode, correlation));
            var two = executor.submit(() -> verifyAfter(start, second, secondCode, correlation));
            start.countDown();
            assertThat(List.of(one.get(), two.get())).containsExactlyInAnyOrder(
                    VerificationResult.VERIFIED, VerificationResult.CONFLICT);
        }
        assertThat(jdbc.queryForObject("select count(*) from verified_identifier where identifier_type='PHONE'",
                Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from verification_challenge where state='CONSUMED'",
                Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from verification_challenge where state='ISSUED'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void promotionRollsBackAtEveryEffectSeam() {
        for (var seam : List.of("challenge_consumed", "identifier_inserted", "indexes_inserted",
                "identity_updated", "audit_inserted")) {
            var target = new CapturingDelivery();
            var failing = service(target,
                    new AesGcmIdentifierEncryptionCapability("seam-enc", (short) 1, key(31)),
                    new HmacBlindIndexCapability("seam-idx", (short) 1, key(32)),
                    new HmacChallengeDigestCapability("seam-dig", (short) 1, key(33)),
                    observed -> {
                        if (seam.equals(observed)) throw new IllegalStateException("injected_failure");
                    });
            var identity = failing.createIdentity(correlation());
            var challenge = failing.issue(identity.identityId(), IdentifierType.EMAIL,
                    seam.replace('_', '-') + "@example.com", Duration.ofMinutes(5), 3, correlation());
            assertThatThrownBy(() -> failing.verify(challenge, target.codes.getFirst(), correlation()))
                    .isInstanceOf(IllegalStateException.class).hasMessage("injected_failure");
            assertThat(jdbc.queryForObject("select state from verification_challenge where challenge_id=?",
                    String.class, challenge)).isEqualTo("ISSUED");
            assertThat(jdbc.queryForObject("select count(*) from verified_identifier where identity_id=?",
                    Integer.class, identity.identityId())).isZero();
            assertThat(jdbc.queryForObject("select security_version from human_identity where identity_id=?",
                    Long.class, identity.identityId())).isEqualTo(1L);
            assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='IDENTIFIER_VERIFIED'",
                    Integer.class)).isZero();
        }
    }

    @Test
    void failureAfterFirstRequiredRotationIndexRollsBackEveryPromotionEffect() {
        var target = new CapturingDelivery();
        var rotatedIndexes = new HmacBlindIndexCapability(
                Map.of((short) 1, "idx-one", (short) 2, "idx-two"), (short) 2,
                java.util.Set.of((short) 1, (short) 2),
                Map.of((short) 1, key(42), (short) 2, key(43)));
        var failing = service(target,
                new AesGcmIdentifierEncryptionCapability("index-seam-enc", (short) 1, key(41)), rotatedIndexes,
                new HmacChallengeDigestCapability("index-seam-dig", (short) 1, key(44)),
                observed -> {
                    if ("index_inserted_1".equals(observed)) throw new IllegalStateException("injected_failure");
                });
        var identity = failing.createIdentity(correlation());
        var challenge = failing.issue(identity.identityId(), IdentifierType.EMAIL, "index-seam@example.com",
                Duration.ofMinutes(5), 3, correlation());
        assertThatThrownBy(() -> failing.verify(challenge, target.codes.getFirst(), correlation()))
                .isInstanceOf(IllegalStateException.class).hasMessage("injected_failure");
        assertThat(jdbc.queryForObject("select state from verification_challenge where challenge_id=?",
                String.class, challenge)).isEqualTo("ISSUED");
        assertThat(jdbc.queryForObject("select count(*) from verified_identifier where identity_id=?",
                Integer.class, identity.identityId())).isZero();
        assertThat(jdbc.queryForObject("select count(*) from verified_identifier_blind_index", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select security_version from human_identity where identity_id=?",
                Long.class, identity.identityId())).isEqualTo(1L);
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='IDENTIFIER_VERIFIED'",
                Integer.class)).isZero();
    }

    @Test
    void concurrentResendLeavesExactlyOneReplacement() throws Exception {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var original = identities.issue(identity.identityId(), IdentifierType.EMAIL, "resend-race@example.com",
                Duration.ofMinutes(5), 3, correlation);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> resendOutcome(start, original, correlation));
            var second = executor.submit(() -> resendOutcome(start, original, correlation));
            start.countDown();
            assertThat(List.of(first.get(), second.get())).containsExactlyInAnyOrder("RESENT", "REJECTED");
        }
        assertThat(jdbc.queryForObject("select count(*) from verification_challenge where identity_id=? "
                + "and state='ISSUED'", Integer.class, identity.identityId())).isEqualTo(1);
    }

    @Test
    void correctWrongAndMaxAttemptRacesHaveOneLegalWinner() throws Exception {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, "verify-race@example.com",
                Duration.ofMinutes(5), 3, correlation);
        var code = delivery.codes.getFirst();
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var correct = executor.submit(() -> verifyAfter(start, challenge, code, correlation));
            var wrong = executor.submit(() -> verifyAfter(start, challenge, "wrong", correlation));
            start.countDown();
            assertThat(List.of(correct.get(), wrong.get())).containsExactlyInAnyOrder(
                    VerificationResult.VERIFIED, VerificationResult.REJECTED);
        }
        assertThat(jdbc.queryForObject("select state from verification_challenge where challenge_id=?",
                String.class, challenge)).isEqualTo("CONSUMED");

        var lockIdentity = identities.createIdentity(correlation);
        var lockChallenge = identities.issue(lockIdentity.identityId(), IdentifierType.PHONE, "+14155550001",
                Duration.ofMinutes(5), 1, correlation);
        var lockStart = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> verifyAfter(lockStart, lockChallenge, "wrong-a", correlation));
            var second = executor.submit(() -> verifyAfter(lockStart, lockChallenge, "wrong-b", correlation));
            lockStart.countDown();
            assertThat(List.of(first.get(), second.get())).containsOnly(VerificationResult.REJECTED);
        }
        assertThat(jdbc.queryForMap("select state,attempt_count from verification_challenge where challenge_id=?",
                lockChallenge)).containsEntry("state", "LOCKED").containsEntry("attempt_count", 1);
    }

    @Test
    void databaseExpiryAndVerifyRaceCannotBeWonWithCallerTime() throws Exception {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, "expiry-race@example.com",
                Duration.ofMinutes(5), 3, correlation);
        owner.update("update verification_challenge set created_at=transaction_timestamp()-interval '2 minutes',"
                + "expires_at=transaction_timestamp() where challenge_id=?", challenge);
        var version = jdbc.queryForObject("select version from verification_challenge where challenge_id=?",
                Long.class, challenge);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var verify = executor.submit(() -> verifyAfter(start, challenge, delivery.codes.getFirst(), correlation));
            var expire = executor.submit(() -> {
                start.await();
                return jdbc.queryForObject("select expire_verification_challenge(?,?)", Integer.class,
                        challenge, version);
            });
            start.countDown();
            assertThat(verify.get()).isEqualTo(VerificationResult.REJECTED);
            assertThat(expire.get()).isIn(1, null);
        }
        assertThat(jdbc.queryForObject("select state from verification_challenge where challenge_id=?",
                String.class, challenge)).isEqualTo("EXPIRED");
        assertThatThrownBy(() -> jdbc.queryForObject(
                "select consume_verification_challenge(?,?,?)", Integer.class, challenge, version,
                Timestamp.from(java.time.Instant.EPOCH))).rootCause().hasMessageContaining("does not exist");
    }

    @Test
    void reconnectPreservesAttemptBudgetAndTerminalState() {
        var correlation = correlation();
        var identity = identities.createIdentity(correlation);
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, "restart@example.com",
                Duration.ofMinutes(5), 2, correlation);
        assertThat(identities.verify(challenge, "wrong", correlation)).isEqualTo(VerificationResult.REJECTED);
        var restarted = service(delivery,
                new AesGcmIdentifierEncryptionCapability("test-encryption", (short) 1, key(1)),
                new HmacBlindIndexCapability("test-index", (short) 1, key(2)),
                new HmacChallengeDigestCapability("test-digest", (short) 1, key(3)));
        assertThat(restarted.verify(challenge, delivery.codes.getFirst(), correlation))
                .isEqualTo(VerificationResult.VERIFIED);
        var restartedAgain = service(delivery,
                new AesGcmIdentifierEncryptionCapability("test-encryption", (short) 1, key(1)),
                new HmacBlindIndexCapability("test-index", (short) 1, key(2)),
                new HmacChallengeDigestCapability("test-digest", (short) 1, key(3)));
        assertThat(restartedAgain.verify(challenge, delivery.codes.getFirst(), correlation))
                .isEqualTo(VerificationResult.REJECTED);
    }

    @Test
    void phoneAndEquivalentDomainsCollideWhileLocalCaseRemainsDistinct() {
        var correlation = correlation();
        var identitiesCreated = java.util.stream.Stream.generate(() -> identities.createIdentity(correlation))
                .limit(6).toList();
        verifyNew(identitiesCreated.get(0), IdentifierType.PHONE, "+14155550100", correlation);
        assertThat(verifyNew(identitiesCreated.get(1), IdentifierType.PHONE, "+14155550100", correlation))
                .isEqualTo(VerificationResult.CONFLICT);
        verifyNew(identitiesCreated.get(2), IdentifierType.EMAIL, "same@BÜCHER.example", correlation);
        assertThat(verifyNew(identitiesCreated.get(3), IdentifierType.EMAIL, "same@xn--bcher-kva.EXAMPLE", correlation))
                .isEqualTo(VerificationResult.CONFLICT);
        assertThat(verifyNew(identitiesCreated.get(4), IdentifierType.EMAIL, "Case@example.com", correlation))
                .isEqualTo(VerificationResult.VERIFIED);
        assertThat(verifyNew(identitiesCreated.get(5), IdentifierType.EMAIL, "case@example.com", correlation))
                .isEqualTo(VerificationResult.VERIFIED);
    }

    @Test
    void privacyCanariesNeverReachPersistenceAuditOutboxLogsErrorsOrResults() {
        var marker = "privacy" + "Canary" + UUID.randomUUID().toString().replace("-", "");
        var email = marker + "@example.invalid";
        var credentialLike = "credential-" + marker;
        var tokenLike = "token-" + marker;
        var logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        var captured = new ListAppender<ILoggingEvent>();
        captured.start();
        logger.addAppender(captured);
        try {
            var correlation = correlation();
            var identity = identities.createIdentity(correlation);
            var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, email,
                    Duration.ofMinutes(5), 3, correlation);
            assertThat(identities.verify(challenge, credentialLike, correlation)).isEqualTo(VerificationResult.REJECTED);
            assertThat(identities.verify(challenge, tokenLike, correlation)).isEqualTo(VerificationResult.REJECTED);
            var result = identities.verify(challenge, delivery.codes.getFirst(), correlation);
            var database = owner.queryForObject("select concat_ws('',"
                    + "(select coalesce(string_agg(row_to_json(v)::text,''),'') from verified_identifier v),"
                    + "(select coalesce(string_agg(row_to_json(b)::text,''),'') from verified_identifier_blind_index b),"
                    + "(select coalesce(string_agg(row_to_json(c)::text,''),'') from verification_challenge c),"
                    + "(select coalesce(string_agg(row_to_json(a)::text,''),'') from audit_fact a),"
                    + "(select coalesce(string_agg(row_to_json(o)::text,''),'') from outbox_event o),"
                    + "(select coalesce(string_agg(row_to_json(d)::text,''),'') from outbox_delivery d))", String.class);
            var applicationLogs = captured.list.stream().map(ILoggingEvent::getFormattedMessage)
                    .collect(java.util.stream.Collectors.joining());
            var postgresLogs = POSTGRES.getLogs();
            var serialized = result.toString() + new SecretChallengeCode(credentialLike)
                    + new NormalizedIdentifier(IdentifierType.EMAIL, (short) 1, email, email);
            for (var canary : List.of(marker, email, credentialLike, tokenLike)) {
                assertThat(database.contains(canary)).isFalse();
                assertThat(applicationLogs.contains(canary)).isFalse();
                assertThat(postgresLogs.contains(canary)).isFalse();
                assertThat(serialized.contains(canary)).isFalse();
            }
            assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isZero();
        } finally {
            logger.detachAppender(captured);
            captured.stop();
        }
    }

    private VerificationResult verifyNew(IdentityReference identity, IdentifierType type, String value,
            CorrelationId correlation) {
        var challenge = identities.issue(identity.identityId(), type, value, Duration.ofMinutes(5), 3, correlation);
        return identities.verify(challenge, delivery.codes.getLast(), correlation);
    }

    private String resendOutcome(CountDownLatch start, String challenge, CorrelationId correlation)
            throws InterruptedException {
        start.await();
        try {
            identities.resend(challenge, "resend-race@example.com", Duration.ofMinutes(5), 3, correlation);
            return "RESENT";
        } catch (ChallengeRejectedException | ChallengeConflictException exception) {
            return "REJECTED";
        }
    }

    private VerificationResult verifyAfter(CountDownLatch start, String challenge, String code,
            CorrelationId correlation) throws InterruptedException {
        start.await();
        return identities.verify(challenge, code, correlation);
    }

    private String issueOutcome(CountDownLatch start, IdentityReference identity, String value,
            CorrelationId correlation) throws InterruptedException {
        start.await();
        try {
            identities.issue(identity.identityId(), IdentifierType.EMAIL, value, Duration.ofMinutes(5), 3, correlation);
            return "ISSUED";
        } catch (ChallengeConflictException exception) {
            assertThat(exception).hasMessage("conflict").hasNoCause();
            return "CONFLICT";
        }
    }

    private IdentityService service(CapturingDelivery target,
            AesGcmIdentifierEncryptionCapability encryption, HmacBlindIndexCapability indexes,
            HmacChallengeDigestCapability digests) {
        return service(target, encryption, indexes, digests, PromotionObserver.NONE);
    }

    private IdentityService service(CapturingDelivery target,
            AesGcmIdentifierEncryptionCapability encryption, HmacBlindIndexCapability indexes,
            HmacChallengeDigestCapability digests, PromotionObserver observer) {
        var source = (DriverManagerDataSource) jdbc.getDataSource();
        return new IdentityService(jdbc,
                new SpringTransactionRunner(new TransactionTemplate(new DataSourceTransactionManager(source))),
                new JdbcAuditFactRepository(jdbc), new IdentifierNormalizer(), encryption, indexes, digests,
                new SequentialMaterials(), target, "test", observer);
    }

    private static byte[] key(int seed) {
        var value = new byte[32];
        for (var index = 0; index < value.length; index++) value[index] = (byte) (seed + index);
        return value;
    }

    private static CorrelationId correlation() { return new CorrelationId("cor_abcdefghijklmnop"); }

    private static final class CapturingDelivery implements ChallengeDeliveryPort {
        final List<String> challengeIds = new ArrayList<>();
        final List<String> codes = new ArrayList<>();
        @Override public void deliver(String challengeId, SecretChallengeCode code) {
            challengeIds.add(challengeId);
            codes.add(code.reveal());
        }
    }
    private static final class SequentialMaterials implements IdentityMaterialGenerator {
        private static final AtomicInteger SEQUENCE = new AtomicInteger();
        private String next(String prefix) { return prefix + String.format("%022d", SEQUENCE.incrementAndGet()); }
        @Override public String identityId() { return next("hid_"); }
        @Override public String identifierId() { return next("vid_"); }
        @Override public String challengeId() { return next("vch_"); }
        @Override public String auditId() { return next("aud_"); }
        @Override public String challengeCode() { return "code-" + String.format("%032d", SEQUENCE.incrementAndGet()); }
    }
}
