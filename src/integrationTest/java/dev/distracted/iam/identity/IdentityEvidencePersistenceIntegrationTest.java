package dev.distracted.iam.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.messaging.CorrelationId;
import dev.distracted.iam.platform.crypto.AesGcmIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.HmacBlindIndexCapability;
import dev.distracted.iam.platform.crypto.HmacChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.CapabilityMetadata;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.CapabilitySelfCheck;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.TokenSignerCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import dev.distracted.iam.platform.persistence.JdbcAuditFactRepository;
import dev.distracted.iam.platform.persistence.SpringTransactionRunner;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.UUID;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.transaction.support.TransactionTemplate;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class IdentityEvidencePersistenceIntegrationTest {
    @Container private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.0-alpine");
    private static final String LOGIN_CREDENTIAL = UUID.randomUUID().toString();
    private static final String RELAY_CREDENTIAL = UUID.randomUUID().toString();
    private static final String UNRELATED_CREDENTIAL = UUID.randomUUID().toString();
    private static final String MIGRATOR_CREDENTIAL = UUID.randomUUID().toString();
    private static JdbcTemplate runtime;
    private static JdbcTemplate owner;
    private static JdbcTemplate relay;
    private static JdbcTemplate unrelated;
    private static JdbcTemplate migrator;
    private static final AtomicInteger EMAIL_SEQUENCE = new AtomicInteger();
    private IdentityService identities;
    private IdentityEvidenceService evidence;
    private Receipt delivery;
    private byte[] fixtureEncryptionKey;
    private byte[] fixtureIndexKey;
    private byte[] fixtureDigestKey;

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role iam_runtime_login login password '" + LOGIN_CREDENTIAL
                    + "' in role iam_runtime");
            statement.execute("create role iam_relay_login login password '" + RELAY_CREDENTIAL
                    + "' in role iam_relay");
            statement.execute("create role iam_unrelated_login login password '" + UNRELATED_CREDENTIAL + "'");
            statement.execute("create role iam_migrator_login login password '" + MIGRATOR_CREDENTIAL
                    + "' in role iam_migrator");
            statement.execute("grant usage,create on schema public to iam_migrator");
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
        runtime = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login",
                LOGIN_CREDENTIAL));
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()));
        relay = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_relay_login",
                RELAY_CREDENTIAL));
        unrelated = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_unrelated_login",
                UNRELATED_CREDENTIAL));
        migrator = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_migrator_login",
                MIGRATOR_CREDENTIAL));
    }

    @BeforeEach
    void setUp() {
        owner.execute("truncate table app_subject,authentication_factor,recovery_method,verified_identifier_blind_index,"
                + "verified_identifier,verification_challenge,human_identity,audit_fact restart identity cascade");
        delivery = new Receipt();
        fixtureEncryptionKey = key(11);
        fixtureIndexKey = key(12);
        fixtureDigestKey = key(13);
        var source = (DriverManagerDataSource) runtime.getDataSource();
        identities = new IdentityService(runtime,
                new SpringTransactionRunner(new TransactionTemplate(new DataSourceTransactionManager(source))),
                new JdbcAuditFactRepository(runtime), new IdentifierNormalizer(),
                new AesGcmIdentifierEncryptionCapability("evidence-encryption", (short) 1, key(1)),
                new HmacBlindIndexCapability("evidence-index", (short) 1, key(2)),
                new HmacChallengeDigestCapability("evidence-digest", (short) 1, key(3)),
                new Materials(), delivery, "test");
        evidence = new IdentityEvidenceService(runtime, new EvidenceMaterials());
    }

    @Test
    void createsEvidenceOnceWithDatabaseTimeAuditAndNoOutbox() {
        var identity = verifiedIdentity();
        var version = evidence.currentIdentityVersion(identity);
        var factor = evidence.ensureEmailOtpFactor(identity, version, correlation());
        var recovery = evidence.ensureVerifiedEmailRecovery(identity, factor.identityVersion(), correlation());
        var factorAgain = evidence.ensureEmailOtpFactor(identity, 1, correlation());
        var recoveryAgain = evidence.ensureVerifiedEmailRecovery(identity, 1, correlation());

        assertThat(factor.outcome()).isEqualTo(EvidenceOutcome.CREATED);
        assertThat(recovery.outcome()).isEqualTo(EvidenceOutcome.CREATED);
        assertThat(factorAgain).isEqualTo(new IdentityEvidence(EvidenceOutcome.EXISTING, factor.evidenceId(),
                recovery.identityVersion(), recovery.securityVersion()));
        assertThat(recoveryAgain).isEqualTo(new IdentityEvidence(EvidenceOutcome.EXISTING, recovery.evidenceId(),
                recovery.identityVersion(), recovery.securityVersion()));
        assertThat(owner.queryForObject("select count(*) from authentication_factor", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from recovery_method", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type in "
                + "('AUTHENTICATION_FACTOR_REGISTERED','RECOVERY_METHOD_REGISTERED')", Integer.class)).isEqualTo(2);
        assertThat(owner.queryForObject("select count(*) from audit_fact where occurred_at<>recorded_at",
                Integer.class)).isZero();
        assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isZero();
    }

    @Test
    void rejectsMissingEmailAndStaleVersionWithoutPartialEffects() {
        var identity = identities.createIdentity(correlation());
        assertThat(evidence.ensureEmailOtpFactor(identity, evidence.currentIdentityVersion(identity), correlation())
                .outcome()).isEqualTo(EvidenceOutcome.REJECTED);
        identity = verifiedIdentity();
        assertThat(evidence.ensureVerifiedEmailRecovery(identity, 1, correlation()).outcome())
                .isEqualTo(EvidenceOutcome.CONFLICT);
        assertThat(owner.queryForObject("select count(*) from authentication_factor", Integer.class)).isZero();
        assertThat(owner.queryForObject("select count(*) from recovery_method", Integer.class)).isZero();
    }

    @Test
    void runtimeCannotWriteOrMutateEvidenceDirectly() {
        assertThatThrownBy(() -> runtime.update("insert into authentication_factor "
                + "(factor_id,identity_id,verified_identifier_id,factor_type,state) values (?,?,?,?,?)",
                "fac_abcdefghijklmnopqrstuv", "hid_abcdefghijklmnopqrstuv", "vid_abcdefghijklmnopqrstuv",
                "EMAIL_OTP", "ACTIVE")).hasRootCauseInstanceOf(java.sql.SQLException.class);
        var identity = verifiedIdentity();
        var created = evidence.ensureEmailOtpFactor(identity, evidence.currentIdentityVersion(identity), correlation());
        assertThatThrownBy(() -> runtime.update("delete from authentication_factor where factor_id=?",
                created.evidenceId())).hasRootCauseInstanceOf(java.sql.SQLException.class);
    }

    @Test
    void evidencePrivilegesAreLeastPrivilegeAndErrorsStaySafe() {
        var identity = verifiedIdentity();
        var created = evidence.ensureEmailOtpFactor(identity, evidence.currentIdentityVersion(identity), correlation());
        var recovery = evidence.ensureVerifiedEmailRecovery(identity, created.identityVersion(), correlation());
        assertThat(runtime.queryForObject("select count(*) from authentication_factor", Integer.class)).isEqualTo(1);
        for (var sql : List.of(
                "insert into authentication_factor(factor_id,identity_id,verified_identifier_id,factor_type,state) "
                        + "select 'fac_abcdefghijklmnopqrstuv',identity_id,verified_identifier_id,factor_type,state "
                        + "from authentication_factor limit 1",
                "update authentication_factor set state='ACTIVE'",
                "delete from authentication_factor",
                "truncate table authentication_factor")) {
            assertThatThrownBy(() -> runtime.execute(sql)).hasRootCauseInstanceOf(java.sql.SQLException.class);
        }
        for (var sql : List.of(
                "insert into recovery_method(recovery_method_id,identity_id,verified_identifier_id,recovery_type,state) "
                        + "select 'rcv_abcdefghijklmnopqrstuv',identity_id,verified_identifier_id,recovery_type,state "
                        + "from recovery_method limit 1",
                "update recovery_method set state='ACTIVE'", "delete from recovery_method",
                "truncate table recovery_method")) {
            assertThatThrownBy(() -> runtime.execute(sql)).hasRootCauseInstanceOf(java.sql.SQLException.class);
        }
        for (var denied : List.of(relay, unrelated)) {
            for (var table : List.of("authentication_factor", "recovery_method")) {
                assertThatThrownBy(() -> denied.queryForObject("select count(*) from " + table, Integer.class))
                        .hasRootCauseInstanceOf(java.sql.SQLException.class);
            }
            assertThatThrownBy(() -> denied.queryForList("select * from ensure_email_otp_factor(?,?,?,?,?)",
                    identity.identityId(), evidence.currentIdentityVersion(identity),
                    "fac_abcdefghijklmnopqrstuv", "aud_abcdefghijklmnopqrstuv", correlation().value()))
                    .hasRootCauseInstanceOf(java.sql.SQLException.class);
        }
        assertThat(owner.queryForObject("select has_table_privilege('public','authentication_factor','select')",
                Boolean.class)).isFalse();
        assertThat(owner.queryForObject("select has_function_privilege('public',"
                + "'ensure_email_otp_factor(text,bigint,text,text,text)','execute')", Boolean.class)).isFalse();
        assertThat(migrator.queryForObject("select count(*) from authentication_factor", Integer.class)).isEqualTo(1);
        assertThatThrownBy(() -> migrator.update("update authentication_factor set state='ACTIVE' where factor_id=?",
                created.evidenceId())).hasRootCauseInstanceOf(java.sql.SQLException.class);
        assertThatThrownBy(() -> migrator.update("delete from authentication_factor where factor_id=?",
                created.evidenceId())).hasRootCauseInstanceOf(java.sql.SQLException.class);
        assertThatThrownBy(() -> migrator.update("update recovery_method set state='ACTIVE' where recovery_method_id=?",
                recovery.evidenceId())).hasRootCauseInstanceOf(java.sql.SQLException.class);
        assertThatThrownBy(() -> migrator.update("delete from recovery_method where recovery_method_id=?",
                recovery.evidenceId())).hasRootCauseInstanceOf(java.sql.SQLException.class);

        var unsafeMaterials = new EvidenceMaterialGenerator() {
            @Override public String factorId() { return "unsafe"; }
            @Override public String recoveryMethodId() { return "unsafe"; }
            @Override public String auditId() { return "unsafe"; }
        };
        var unsafe = new IdentityEvidenceService(runtime, unsafeMaterials);
        var another = verifiedIdentity();
        assertThatThrownBy(() -> unsafe.ensureVerifiedEmailRecovery(another,
                evidence.currentIdentityVersion(another), correlation()))
                .isInstanceOf(IdentityEvidenceRejectedException.class)
                .hasMessage("identity_evidence_rejected").hasNoCause();
        assertThatThrownBy(() -> unsafe.ensureEmailOtpFactor(another,
                evidence.currentIdentityVersion(another), correlation()))
                .isInstanceOf(IdentityEvidenceRejectedException.class)
                .hasMessage("identity_evidence_rejected").hasNoCause();
    }

    @Test
    void runtimePrivacyCanariesNeverEscapeProtectedBoundary() {
        var marker = String.join("", "w2Privacy", UUID.randomUUID().toString().replace("-", ""));
        var email = marker + "@privacy.invalid";
        var challengeCanary = String.join("", "challenge-", marker);
        var credentialCanary = String.join("", "credential-", marker);
        var privateKeyCanary = String.join("", "private-material-", marker);
        var accessCanary = String.join("", "access-value-", marker);
        var refreshCanary = String.join("", "refresh-value-", marker);
        var logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        var captured = new ListAppender<ILoggingEvent>();
        captured.start();
        logger.addAppender(captured);
        try {
            var identity = identities.createIdentity(correlation());
            var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, email,
                    Duration.ofMinutes(10), 10, correlation());
            for (var rejected : List.of(challengeCanary, credentialCanary, privateKeyCanary, accessCanary,
                    refreshCanary)) {
                assertThat(identities.verify(challenge, rejected, correlation())).isEqualTo(VerificationResult.REJECTED);
            }
            assertThat(identities.verify(challenge, delivery.code, correlation())).isEqualTo(VerificationResult.VERIFIED);
            var factor = evidence.ensureEmailOtpFactor(identity, evidence.currentIdentityVersion(identity), correlation());
            var recovery = evidence.ensureVerifiedEmailRecovery(identity, factor.identityVersion(), correlation());
            var database = owner.queryForObject("select concat_ws('',"
                    + "(select coalesce(string_agg(row_to_json(i)::text,''),'') from human_identity i),"
                    + "(select coalesce(string_agg(row_to_json(v)::text,''),'') from verified_identifier v),"
                    + "(select coalesce(string_agg(row_to_json(b)::text,''),'') from verified_identifier_blind_index b),"
                    + "(select coalesce(string_agg(row_to_json(c)::text,''),'') from verification_challenge c),"
                    + "(select coalesce(string_agg(row_to_json(f)::text,''),'') from authentication_factor f),"
                    + "(select coalesce(string_agg(row_to_json(r)::text,''),'') from recovery_method r),"
                    + "(select coalesce(string_agg(row_to_json(a)::text,''),'') from audit_fact a),"
                    + "(select coalesce(string_agg(row_to_json(o)::text,''),'') from outbox_event o),"
                    + "(select coalesce(string_agg(row_to_json(d)::text,''),'') from outbox_delivery d))", String.class);
            var logs = captured.list.stream().map(ILoggingEvent::getFormattedMessage)
                    .collect(java.util.stream.Collectors.joining());
            var serialized = factor + recovery.toString() + new SecretChallengeCode(challengeCanary);
            for (var canary : List.of(marker, email, challengeCanary, credentialCanary, privateKeyCanary,
                    accessCanary, refreshCanary)) {
                assertThat(database.contains(canary)).isFalse();
                assertThat(logs.contains(canary)).isFalse();
                assertThat(POSTGRES.getLogs().contains(canary)).isFalse();
                assertThat(serialized.contains(canary)).isFalse();
            }
            assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isZero();
            assertThat(owner.queryForObject("select count(*) from outbox_delivery", Integer.class)).isZero();
        } finally {
            logger.detachAppender(captured);
            captured.stop();
        }
    }

    @Test
    void v4RejectsEveryClosedShapeOwnershipUniquenessAndAuditPairViolation() {
        var identity = verifiedIdentity();
        var identifier = owner.queryForObject("select identifier_id from verified_identifier where identity_id=?",
                String.class, identity.identityId());
        var factor = evidence.ensureEmailOtpFactor(identity, evidence.currentIdentityVersion(identity), correlation());
        assertThat(owner.queryForMap("select factor_type,state,version,created_at is not null as created_ok,"
                + "updated_at is not null as updated_ok from authentication_factor where factor_id=?",
                factor.evidenceId())).containsEntry("factor_type", "EMAIL_OTP")
                .containsEntry("state", "ACTIVE").containsEntry("version", 1L)
                .containsEntry("created_ok", true).containsEntry("updated_ok", true);
        var second = verifiedIdentity();
        var secondIdentifier = owner.queryForObject(
                "select identifier_id from verified_identifier where identity_id=?", String.class, second.identityId());

        assertFactorRejected("bad", second.identityId(), secondIdentifier, "EMAIL_OTP", "ACTIVE", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", "hid_missingabcdefghijklmnop", secondIdentifier,
                "EMAIL_OTP", "ACTIVE", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", second.identityId(), "vid_missingabcdefghijklmnop",
                "EMAIL_OTP", "ACTIVE", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", second.identityId(), identifier,
                "EMAIL_OTP", "ACTIVE", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "PASSWORD", "ACTIVE", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "EMAIL_OTP", "DISABLED", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "EMAIL_OTP", "ACTIVE", 2, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", identity.identityId(), identifier,
                "EMAIL_OTP", "ACTIVE", 1, false);
        assertFactorRejected("fac_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "EMAIL_OTP", "ACTIVE", 1, true);

        assertRecoveryRejected("bad", second.identityId(), secondIdentifier, "VERIFIED_EMAIL", "ACTIVE", 1, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", "hid_missingabcdefghijklmnop", secondIdentifier,
                "VERIFIED_EMAIL", "ACTIVE", 1, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), "vid_missingabcdefghijklmnop",
                "VERIFIED_EMAIL", "ACTIVE", 1, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), identifier,
                "VERIFIED_EMAIL", "ACTIVE", 1, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "EMAIL_OTP", "ACTIVE", 1, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "VERIFIED_EMAIL", "DISABLED", 1, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "VERIFIED_EMAIL", "ACTIVE", 2, false);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "VERIFIED_EMAIL", "ACTIVE", 1, true);
        var recovery = evidence.ensureVerifiedEmailRecovery(second, evidence.currentIdentityVersion(second), correlation());
        assertThat(recovery.outcome()).isEqualTo(EvidenceOutcome.CREATED);
        assertRecoveryRejected("rcv_abcdefghijklmnopqrstuv", second.identityId(), secondIdentifier,
                "VERIFIED_EMAIL", "ACTIVE", 1, false);
        assertThat(owner.queryForMap("select recovery_type,state,version,created_at is not null as created_ok,"
                + "updated_at is not null as updated_ok from recovery_method where recovery_method_id=?",
                recovery.evidenceId())).containsEntry("recovery_type", "VERIFIED_EMAIL")
                .containsEntry("state", "ACTIVE").containsEntry("version", 1L)
                .containsEntry("created_ok", true).containsEntry("updated_ok", true);
        assertThat(owner.queryForObject("select count(*) from pg_constraint where conrelid='recovery_method'::regclass "
                + "and contype='u'", Integer.class)).isEqualTo(2);

        assertThatThrownBy(() -> owner.update("insert into audit_fact(audit_id,fact_type,subject_kind,subject_id,"
                + "outcome,correlation_id,occurred_at) values (?,?,?,?,?,?,transaction_timestamp())",
                "aud_abcdefghijklmnopqrstuv", "AUTHENTICATION_FACTOR_REGISTERED", "RECOVERY_METHOD",
                "rcv_abcdefghijklmnopqrstuv", "SUCCEEDED", correlation().value()))
                .hasRootCauseInstanceOf(java.sql.SQLException.class);
        assertThatThrownBy(() -> owner.update("insert into audit_fact(audit_id,fact_type,subject_kind,subject_id,"
                + "outcome,correlation_id,occurred_at) values (?,?,?,?,?,?,transaction_timestamp())",
                "aud_abcdefghijklmnopqrstuv", "RECOVERY_METHOD_REGISTERED", "AUTHENTICATION_FACTOR",
                "fac_abcdefghijklmnopqrstuv", "SUCCEEDED", correlation().value()))
                .hasRootCauseInstanceOf(java.sql.SQLException.class);
    }

    private void assertFactorRejected(String factorId, String identityId, String identifierId, String type,
            String state, long version, boolean nullTimestamps) {
        var sql = "insert into authentication_factor(factor_id,identity_id,verified_identifier_id,factor_type,state,"
                + "version" + (nullTimestamps ? ",created_at,updated_at" : "") + ") values (?,?,?,?,?,?"
                + (nullTimestamps ? ",null,null" : "") + ")";
        assertThatThrownBy(() -> owner.update(sql, factorId, identityId, identifierId, type, state, version))
                .hasRootCauseInstanceOf(java.sql.SQLException.class);
    }

    private void assertRecoveryRejected(String recoveryId, String identityId, String identifierId, String type,
            String state, long version, boolean nullTimestamps) {
        var sql = "insert into recovery_method(recovery_method_id,identity_id,verified_identifier_id,recovery_type,state,"
                + "version" + (nullTimestamps ? ",created_at,updated_at" : "") + ") values (?,?,?,?,?,?"
                + (nullTimestamps ? ",null,null" : "") + ")";
        assertThatThrownBy(() -> owner.update(sql, recoveryId, identityId, identifierId, type, state, version))
                .hasRootCauseInstanceOf(java.sql.SQLException.class);
    }

    @Test
    void concurrentEnsuresHaveOneCreatorAndOneStableExistingResult() throws Exception {
        var identity = verifiedIdentity();
        var expected = evidence.currentIdentityVersion(identity);
        var start = new CountDownLatch(1);
        List<IdentityEvidence> factorResults;
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> ensureFactorAfter(start, identity, expected));
            var second = executor.submit(() -> ensureFactorAfter(start, identity, expected));
            start.countDown();
            factorResults = List.of(first.get(), second.get());
        }
        assertThat(factorResults).extracting(IdentityEvidence::outcome)
                .containsExactlyInAnyOrder(EvidenceOutcome.CREATED, EvidenceOutcome.EXISTING);
        assertThat(factorResults).extracting(IdentityEvidence::evidenceId)
                .containsOnly(factorResults.getFirst().evidenceId());

        var recoveryVersion = evidence.currentIdentityVersion(identity);
        var recoveryStart = new CountDownLatch(1);
        List<IdentityEvidence> recoveryResults;
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> ensureRecoveryAfter(recoveryStart, identity, recoveryVersion));
            var second = executor.submit(() -> ensureRecoveryAfter(recoveryStart, identity, recoveryVersion));
            recoveryStart.countDown();
            recoveryResults = List.of(first.get(), second.get());
        }
        assertThat(recoveryResults).extracting(IdentityEvidence::outcome)
                .containsExactlyInAnyOrder(EvidenceOutcome.CREATED, EvidenceOutcome.EXISTING);
        assertThat(recoveryResults).extracting(IdentityEvidence::evidenceId)
                .containsOnly(recoveryResults.getFirst().evidenceId());
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type in "
                + "('AUTHENTICATION_FACTOR_REGISTERED','RECOVERY_METHOD_REGISTERED')", Integer.class)).isEqualTo(2);
    }

    @Test
    void injectedFailuresAtEveryEvidenceBoundaryRollBackFactorAndRecovery() {
        for (var kind : List.of("factor", "recovery")) {
            for (var seam : List.of("evidence", "version", "audit")) {
                var identity = verifiedIdentity();
                var beforeVersion = evidence.currentIdentityVersion(identity);
                installFailureTrigger(kind, seam);
                try {
                    var operation = (org.assertj.core.api.ThrowableAssert.ThrowingCallable) () -> {
                        if ("factor".equals(kind)) {
                            evidence.ensureEmailOtpFactor(identity, beforeVersion, correlation());
                        } else {
                            evidence.ensureVerifiedEmailRecovery(identity, beforeVersion, correlation());
                        }
                    };
                    assertThatThrownBy(operation).isInstanceOf(IdentityEvidenceRejectedException.class)
                            .hasMessage("identity_evidence_rejected").hasNoCause();
                } finally {
                    removeFailureTrigger(kind, seam);
                }
                assertThat(evidence.currentIdentityVersion(identity)).isEqualTo(beforeVersion);
                assertThat(owner.queryForObject("select count(*) from " + evidenceTable(kind)
                        + " where identity_id=?", Integer.class, identity.identityId())).isZero();
                assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type=? and subject_id like ?",
                        Integer.class, factType(kind), prefix(kind) + "%")).isZero();
            }
        }
    }

    @Test
    void deterministicFixtureUsesAHealthySpringGraphAndConvergesAcrossContextRestart() {
        try (var first = fixtureContext()) {
            assertHealthyFixtureGraph(first);
        }
        try (var restarted = fixtureContext()) {
            assertHealthyFixtureGraph(restarted);
        }
        assertThat(owner.queryForObject("select count(*) from human_identity", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from verified_identifier", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from verification_challenge", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from authentication_factor", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from recovery_method", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isZero();
    }

    @Test
    void retainedV3MigratesToV4PreservesIdentityAndRerunIsNoOp() {
        owner.execute("create database retained_w2_v3");
        var url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort()
                + "/retained_w2_v3";
        var v3 = Flyway.configure().dataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword())
                .target(MigrationVersion.fromVersion("3")).load();
        assertThat(v3.migrate().migrationsExecuted).isEqualTo(3);
        var retained = new JdbcTemplate(new DriverManagerDataSource(url, POSTGRES.getUsername(),
                POSTGRES.getPassword()));
        retained.update("insert into human_identity(identity_id,state,security_version,version) values (?,?,?,?)",
                "hid_retainedV3Identity000001", "ACTIVE", 2, 2);
        retained.update("insert into verified_identifier(identifier_id,identity_id,identifier_type,normalization_version,"
                        + "canonical_ciphertext,canonical_nonce,canonical_tag,display_ciphertext,display_nonce,display_tag,"
                        + "encryption_key_version,verified_at) values (?,?,?,?,?,?,?,?,?,?,?,transaction_timestamp())",
                "vid_retainedV3Email00000001", "hid_retainedV3Identity000001", "EMAIL", 1,
                new byte[] {1}, new byte[12], new byte[16], new byte[] {2}, new byte[12], new byte[16], 1);
        var latest = Flyway.configure().dataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword()).load();
        assertThat(latest.migrate().migrationsExecuted).isEqualTo(10);
        assertThat(latest.migrate().migrationsExecuted).isZero();
        assertThat(retained.queryForObject("select count(*) from human_identity where identity_id=?", Integer.class,
                "hid_retainedV3Identity000001")).isEqualTo(1);
        assertThat(retained.queryForObject("select count(*) from verified_identifier where identifier_id=?",
                Integer.class, "vid_retainedV3Email00000001")).isEqualTo(1);
        assertThat(retained.queryForObject("select count(*) from authentication_factor", Integer.class)).isZero();
        assertThat(retained.queryForObject("select count(*) from recovery_method", Integer.class)).isZero();
    }

    private AnnotationConfigApplicationContext fixtureContext() {
        var context = new AnnotationConfigApplicationContext();
        context.getEnvironment().setActiveProfiles("test");
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("fixture-test",
                java.util.Map.of("iam.fixtures.deterministic-identity.enabled", "true")));
        var source = (DriverManagerDataSource) runtime.getDataSource();
        context.registerBean(javax.sql.DataSource.class, () -> source);
        context.registerBean(JdbcTemplate.class, () -> new JdbcTemplate(source));
        context.registerBean(org.springframework.transaction.PlatformTransactionManager.class,
                () -> new DataSourceTransactionManager(source));
        context.registerBean(StructuredIdentifierEncryptionCapability.class,
                () -> new AesGcmIdentifierEncryptionCapability("fixture-encryption", (short) 1,
                        fixtureEncryptionKey));
        context.registerBean(VersionedBlindIndexCapability.class,
                () -> new HmacBlindIndexCapability("fixture-index", (short) 1, fixtureIndexKey));
        context.registerBean(dev.distracted.iam.platform.crypto.ChallengeDigestCapability.class,
                () -> new HmacChallengeDigestCapability("fixture-digest", (short) 1, fixtureDigestKey));
        context.registerBean(TokenSignerCapability.class, TestSigner::new);
        context.register(IdentityApplicationConfiguration.class,
                dev.distracted.iam.identity.fixture.FixtureSafetyConfiguration.class,
                dev.distracted.iam.identity.fixture.DeterministicIdentityFixtureConfiguration.class);
        context.refresh();
        return context;
    }

    private IdentityEvidence ensureFactorAfter(CountDownLatch start, IdentityReference identity, long version)
            throws InterruptedException {
        start.await();
        return evidence.ensureEmailOtpFactor(identity, version, correlation());
    }

    private IdentityEvidence ensureRecoveryAfter(CountDownLatch start, IdentityReference identity, long version)
            throws InterruptedException {
        start.await();
        return evidence.ensureVerifiedEmailRecovery(identity, version, correlation());
    }

    private void installFailureTrigger(String kind, String seam) {
        var triggerName = "w2_" + kind + "_" + seam;
        var table = switch (seam) {
            case "evidence" -> evidenceTable(kind);
            case "version" -> "human_identity";
            case "audit" -> "audit_fact";
            default -> throw new IllegalArgumentException("unknown_test_seam");
        };
        owner.execute("create or replace function " + triggerName + "() returns trigger language plpgsql as $$ "
                + "begin raise exception 'injected w2 failure' using errcode='55000'; end $$");
        owner.execute("create trigger " + triggerName + " after " + ("version".equals(seam) ? "update" : "insert")
                + " on " + table + " for each row execute function " + triggerName + "()");
    }

    private void removeFailureTrigger(String kind, String seam) {
        var triggerName = "w2_" + kind + "_" + seam;
        var table = switch (seam) {
            case "evidence" -> evidenceTable(kind);
            case "version" -> "human_identity";
            case "audit" -> "audit_fact";
            default -> throw new IllegalArgumentException("unknown_test_seam");
        };
        owner.execute("drop trigger if exists " + triggerName + " on " + table);
        owner.execute("drop function if exists " + triggerName + "()");
    }

    private static String evidenceTable(String kind) {
        return "factor".equals(kind) ? "authentication_factor" : "recovery_method";
    }

    private static String factType(String kind) {
        return "factor".equals(kind) ? "AUTHENTICATION_FACTOR_REGISTERED" : "RECOVERY_METHOD_REGISTERED";
    }

    private static String prefix(String kind) { return "factor".equals(kind) ? "fac_" : "rcv_"; }

    private static void assertHealthyFixtureGraph(AnnotationConfigApplicationContext context) {
        assertThat(context.getBeanNamesForType(
                load("dev.distracted.iam.identity.fixture.DeterministicIdentityFixtureRunner"))).hasSize(1);
        assertThat(context.getBeanNamesForType(
                load("dev.distracted.iam.identity.fixture.OneShotChallengeReceipt"))).hasSize(1);
        assertThat(context.getBeanNamesForType(ChallengeDeliveryPort.class)).hasSize(1);
        assertThat(context.getBeanNamesForType(UserDetailsService.class)).isEmpty();
        assertThat(context.getBeanNamesForType(JwtEncoder.class)).isEmpty();
        assertThat(context.getBeanNamesForType(SecurityFilterChain.class)).isEmpty();
        assertThat(java.util.Arrays.stream(context.getBeanDefinitionNames()))
                .noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).matches(".*(controller|endpoint|fallback|generated).*"));
    }

    private static Class<?> load(String type) {
        try {
            return Class.forName(type);
        } catch (ClassNotFoundException exception) {
            throw new AssertionError("expected fixture graph type missing");
        }
    }

    private static final class TestSigner implements TokenSignerCapability {
        @Override public byte[] sign(byte[] signingInput) { return signingInput.clone(); }
        @Override public CapabilityMetadata metadata() {
            return new CapabilityMetadata(CapabilityPurpose.ACCESS_TOKEN_SIGNING, "test-provider",
                    "fixture-signing", "ES256");
        }
        @Override public CapabilitySelfCheck selfCheck() { return CapabilitySelfCheck.ready(); }
    }

    private IdentityReference verifiedIdentity() {
        var identity = identities.createIdentity(correlation());
        var email = "factor+" + EMAIL_SEQUENCE.incrementAndGet() + "@test.invalid";
        var challenge = identities.issue(identity.identityId(), IdentifierType.EMAIL, email,
                Duration.ofMinutes(10), 3, correlation());
        assertThat(identities.verify(challenge, delivery.code, correlation())).isEqualTo(VerificationResult.VERIFIED);
        return identity;
    }

    private static byte[] key(int seed) {
        var key = new byte[32];
        new java.security.SecureRandom(new byte[] {(byte) seed}).nextBytes(key);
        return key;
    }

    private static CorrelationId correlation() { return new CorrelationId("cor_abcdefghijklmnop"); }

    private static final class Receipt implements ChallengeDeliveryPort {
        private String code;
        @Override public void deliver(String challengeId, SecretChallengeCode challengeCode) {
            code = challengeCode.reveal();
        }
    }

    private static final class Materials implements IdentityMaterialGenerator {
        private static final AtomicInteger SEQUENCE = new AtomicInteger();
        private String next(String prefix) { return prefix + String.format("%022d", SEQUENCE.incrementAndGet()); }
        @Override public String identityId() { return next("hid_"); }
        @Override public String identifierId() { return next("vid_"); }
        @Override public String challengeId() { return next("vch_"); }
        @Override public String auditId() { return "aud_E" + String.format("%021d", SEQUENCE.incrementAndGet()); }
        @Override public String challengeCode() { return next(""); }
    }

    private static final class EvidenceMaterials implements EvidenceMaterialGenerator {
        private static final AtomicInteger SEQUENCE = new AtomicInteger();
        private String next(String prefix) { return prefix + String.format("%022d", SEQUENCE.incrementAndGet()); }
        @Override public String factorId() { return next("fac_"); }
        @Override public String recoveryMethodId() { return next("rcv_"); }
        @Override public String auditId() { return next("aud_"); }
    }
}
