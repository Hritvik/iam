package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.DriverManager;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class DpopPersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static JdbcTemplate owner;
    private static JdbcTemplate runtime;

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role unrelated_service nologin");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD + "' in role iam_runtime");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()).load().migrate();
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
        runtime = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD));
        owner.queryForObject("select reconcile_pinned_registration(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                "dutch-development", (short) 1, "Dutch Development", "development",
                "eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc",
                "dutch-mobile", "NATIVE_PUBLIC", "EXTERNAL", new String[] {"dutch://oauth/callback"},
                new String[] {"authorization_code"}, new String[] {"S256"}, "dutch-api",
                "https://api.dutch.invalid", new String[] {"member:read"}, true, "S256",
                new String[] {"verified_identifier", "usable_factor", "recovery_path"});
    }

    @Test
    void aNonceAndReplayIdentityAreConsumedExactlyOnceWithoutRawProofState() {
        var nonceDigest = bytes(1);
        var thumbprintDigest = bytes(2);
        var targetDigest = bytes(3);
        var replayDigest = bytes(4);
        var issued = runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_0123456789012345678901", nonceDigest, (short) 1, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprintDigest, "POST", targetDigest, digests(bytes(5)), versions((short) 1), 180,
                120, "cor_0123456789012345");

        var mismatched = runtime.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)",
                String.class, digests(nonceDigest), versions((short) 1), "TOKEN", "dutch-development", "dutch-mobile",
                digests(thumbprintDigest), "POST", digests(bytes(99)), digests(replayDigest), versions((short) 1),
                180, "cor_0123456789012346");

        var first = runtime.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                digests(nonceDigest), versions((short) 1), "TOKEN", "dutch-development", "dutch-mobile",
                digests(thumbprintDigest), "POST", digests(targetDigest), digests(replayDigest), versions((short) 1),
                180, "cor_1123456789012345");
        var second = runtime.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                digests(nonceDigest), versions((short) 1), "TOKEN", "dutch-development", "dutch-mobile",
                digests(thumbprintDigest), "POST", digests(targetDigest), digests(replayDigest), versions((short) 1),
                180, "cor_2123456789012345");

        assertThat(issued.get("result")).isEqualTo("ISSUED");
        assertThat(mismatched).isEqualTo("REJECTED");
        assertThat(first).isEqualTo("CONSUMED");
        assertThat(second).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select count(*) from dpop_nonce where nonce_id=? and status='CONSUMED'",
                Integer.class, "dpn_0123456789012345678901")).isOne();
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest=?",
                Integer.class, replayDigest)).isOne();
    }

    @Test
    void nullableResourceReplayArgumentsFailClosedWithoutRowsOrDatabaseDetails() {
        assertThat(runtime.queryForObject("select claim_dpop_resource_replay(?,?,?)", Boolean.class,
                digests(bytes(21)), versions((short) 1), null)).isFalse();
        assertThat(runtime.queryForObject("select claim_dpop_resource_replay(?,?,?)", Boolean.class,
                null, versions((short) 1), 180)).isFalse();
        assertThat(runtime.queryForObject("select claim_dpop_resource_replay(?,?,?)", Boolean.class,
                digests(bytes(22)), null, 180)).isFalse();
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest in (?,?)",
                Integer.class, bytes(21), bytes(22))).isZero();
    }

    @Test
    void v9ObjectsHaveExactOwnersFunctionAuthorityAndNoRuntimeTableAuthority() {
        for (var table : java.util.List.of("dpop_nonce", "dpop_replay", "token_issuance_audit_fact")) {
            assertThat(owner.queryForObject("select tableowner from pg_tables where schemaname='public' and tablename=?",
                    String.class, table)).isEqualTo("iam_migrator");
            for (var role : java.util.List.of("iam_runtime", "iam_registration_reconciler", "iam_relay",
                    "unrelated_service", "public")) {
                for (var operation : java.util.List.of("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")) {
                    assertThat(owner.queryForObject("select has_table_privilege(?,?,?)", Boolean.class,
                            role, "public." + table, operation)).as(role + " " + table + " " + operation).isFalse();
                }
            }
        }
        var functions = java.util.List.of(
                "issue_dpop_nonce(text,bytea,smallint,text,text,text,bytea,text,bytea,bytea[],smallint[],integer,integer,text,bytea[],bytea[])",
                "consume_dpop_nonce_and_claim_replay(bytea[],smallint[],text,text,text,bytea[],text,bytea[],bytea[],smallint[],integer,text)",
                "claim_dpop_resource_replay(bytea[],smallint[],integer)",
                "append_token_issuance_audit(text,text,text,text,text)",
                "read_active_token_security_context(text,text,text,text)",
                "cleanup_expired_dpop_state(integer)");
        for (var function : functions) {
            assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',?,'EXECUTE')", Boolean.class,
                    "public." + function)).isTrue();
            for (var role : java.util.List.of("public", "iam_registration_reconciler", "iam_relay", "unrelated_service")) {
                assertThat(owner.queryForObject("select has_function_privilege(?,?,'EXECUTE')", Boolean.class,
                        role, "public." + function)).as(role + " " + function).isFalse();
            }
            var metadata = owner.queryForMap("select r.rolname owner,p.prosecdef,p.provolatile,"
                    + "coalesce(array_to_string(p.proconfig,','),'') settings from pg_proc p "
                    + "join pg_roles r on r.oid=p.proowner where p.oid=?::regprocedure", "public." + function);
            assertThat(metadata.get("owner")).isEqualTo("iam_migrator");
            assertThat(metadata.get("prosecdef")).isEqualTo(true);
            assertThat(metadata.get("provolatile")).isEqualTo("v");
            assertThat(metadata.get("settings").toString()).contains("search_path=pg_catalog, public");
        }
    }

    @Test
    void concurrentResourceReplayClaimsHaveExactlyOneWinnerAcrossConnections() throws Exception {
        var digest = bytes(31);
        var barrier = new java.util.concurrent.CyclicBarrier(2);
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var claims = java.util.stream.IntStream.range(0, 2).mapToObj(ignored -> executor.submit(() -> {
                var isolated = new JdbcTemplate(new DriverManagerDataSource(
                        POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD));
                barrier.await(10, java.util.concurrent.TimeUnit.SECONDS);
                return isolated.queryForObject("select claim_dpop_resource_replay(?,?,?)", Boolean.class,
                        digests(digest), versions((short) 1), 180);
            })).toList();
            assertThat(claims.stream().map(future -> {
                try { return future.get(15, java.util.concurrent.TimeUnit.SECONDS); }
                catch (Exception exception) { throw new AssertionError(exception); }
            }).filter(Boolean::booleanValue).count()).isOne();
        }
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest=?",
                Integer.class, digest)).isOne();
    }

    @Test
    void boundedCleanupRemovesOnlyTheRequestedNumberOfExpiredReplayRows() {
        for (int index = 40; index < 43; index++) {
            owner.update("insert into dpop_replay(replay_digest,digest_key_version,purpose,expires_at,created_at) "
                    + "values(?,1,'RESOURCE',transaction_timestamp()-interval '1 second',transaction_timestamp()-interval '2 seconds')",
                    bytes(index));
        }
        owner.update("insert into dpop_replay(replay_digest,digest_key_version,purpose,expires_at) "
                + "values(?,1,'RESOURCE',transaction_timestamp()+interval '5 minutes')", bytes(43));

        assertThat(runtime.queryForObject("select cleanup_expired_dpop_state(?)", Integer.class, 2)).isEqualTo(2);
        assertThat(owner.queryForObject("select count(*) from dpop_replay where expires_at<=transaction_timestamp()",
                Integer.class)).isOne();
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest=?",
                Integer.class, bytes(43))).isOne();
        assertThat(runtime.queryForObject("select cleanup_expired_dpop_state(?)", Integer.class, 0)).isZero();
        assertThat(runtime.queryForObject("select cleanup_expired_dpop_state(?)", Integer.class, (Object) null)).isZero();
    }

    @Test
    void issuingANewNonceSupersedesTheExistingLiveBinding() {
        var thumbprint = bytes(51);
        var target = bytes(52);
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_1123456789012345678901", bytes(53), (short) 1, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprint, "POST", target, digests(bytes(55)), versions((short) 1), 180,
                120, "cor_3123456789012345");
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_2123456789012345678901", bytes(54), (short) 2, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprint, "POST", target, digests(bytes(56)), versions((short) 2), 180,
                120, "cor_4123456789012345");

        assertThat(owner.queryForObject("select status from dpop_nonce where nonce_id=?", String.class,
                "dpn_1123456789012345678901")).isEqualTo("SUPERSEDED");
        assertThat(owner.queryForObject("select version from dpop_nonce where nonce_id=?", Long.class,
                "dpn_1123456789012345678901")).isEqualTo(2L);
        assertThat(owner.queryForObject("select status from dpop_nonce where nonce_id=?", String.class,
                "dpn_2123456789012345678901")).isEqualTo("ISSUED");
    }

    @Test
    void activeSecurityContextIsReadThroughCanonicalBindingAndFailsClosed() {
        var identity = "hid_0123456789012345678901";
        var subject = "aps_012345678901234567890123";
        owner.update("insert into human_identity(identity_id,state,security_version) values(?,'ACTIVE',7)", identity);
        owner.update("insert into app_subject(app_registration_id,human_identity_id,app_subject) values(?,?,?)",
                "dutch-development", identity, subject);

        var active = runtime.queryForMap("select * from read_active_token_security_context(?,?,?,?)",
                identity, "dutch-development", "dutch-mobile", subject);
        var nullResult = runtime.queryForMap("select * from read_active_token_security_context(?,?,?,?)",
                null, "dutch-development", "dutch-mobile", subject);
        var wrongClient = runtime.queryForMap("select * from read_active_token_security_context(?,?,?,?)",
                identity, "dutch-development", "other-client", subject);
        var wrongSubject = runtime.queryForMap("select * from read_active_token_security_context(?,?,?,?)",
                identity, "dutch-development", "dutch-mobile", "aps_112345678901234567890123");
        owner.update("update human_identity set state='DISABLED',version=version+1 where identity_id=?", identity);
        var disabled = runtime.queryForMap("select * from read_active_token_security_context(?,?,?,?)",
                identity, "dutch-development", "dutch-mobile", subject);

        assertThat(active).containsEntry("result", "ACTIVE").containsEntry("security_version", 7L);
        assertThat(nullResult.get("result")).isEqualTo("REJECTED");
        assertThat(wrongClient.get("result")).isEqualTo("REJECTED");
        assertThat(wrongSubject.get("result")).isEqualTo("REJECTED");
        assertThat(disabled.get("result")).isEqualTo("REJECTED");
    }

    @Test
    void duplicateChallengeProofReplayDoesNotSupersedeTheLiveNonce() {
        var thumbprint = bytes(71);
        var target = bytes(72);
        var replay = bytes(73);
        var first = runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_3123456789012345678901", bytes(74), (short) 1, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprint, "POST", target, digests(replay), versions((short) 1), 180,
                120, "cor_5123456789012345");
        var duplicate = runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_4123456789012345678901", bytes(75), (short) 1, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprint, "POST", target, digests(replay), versions((short) 1), 180,
                120, "cor_6123456789012345");

        assertThat(first.get("result")).isEqualTo("ISSUED");
        assertThat(duplicate.get("result")).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select status from dpop_nonce where nonce_id=?", String.class,
                "dpn_3123456789012345678901")).isEqualTo("ISSUED");
        assertThat(owner.queryForObject("select count(*) from dpop_nonce where nonce_id=?", Integer.class,
                "dpn_4123456789012345678901")).isZero();
    }

    @Test
    void outerIssuanceTransactionRollsBackNonceAndReplayClaimsOnLaterFailure() {
        var nonce = bytes(81);
        var thumbprint = bytes(82);
        var target = bytes(83);
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_5123456789012345678901", nonce, (short) 1, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprint, "POST", target, digests(bytes(84)), versions((short) 1), 180,
                120, "cor_7123456789012345");
        var dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD);
        var transactions = new org.springframework.transaction.support.TransactionTemplate(
                new org.springframework.jdbc.datasource.DataSourceTransactionManager(dataSource));
        var isolated = new JdbcTemplate(dataSource);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
            assertThat(isolated.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)",
                    String.class, digests(nonce), versions((short) 1), "TOKEN", "dutch-development", "dutch-mobile",
                    digests(thumbprint), "POST", digests(target), digests(bytes(85)), versions((short) 1), 180,
                    "cor_8123456789012345")).isEqualTo("CONSUMED");
            throw new IllegalStateException("injected_after_replay");
        })).isInstanceOf(IllegalStateException.class).hasMessage("injected_after_replay");

        assertThat(owner.queryForObject("select status from dpop_nonce where digest=?", String.class, nonce))
                .isEqualTo("ISSUED");
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest=?",
                Integer.class, bytes(85))).isZero();
    }

    @Test
    void resourceNonceIsSingleUseAndReplayAliasesSurviveDigestKeyRotation() {
        var nonceV1 = bytes(91);
        var nonceV2 = bytes(92);
        var thumbV1 = bytes(93);
        var thumbV2 = bytes(94);
        var targetV1 = bytes(95);
        var targetV2 = bytes(96);
        var replayV1 = bytes(97);
        var replayV2 = bytes(98);
        var issued = runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_6123456789012345678901", nonceV1, (short) 1, "RESOURCE", "dutch-development",
                "dutch-mobile", thumbV1, "GET", targetV1, new byte[][] {replayV2, replayV1},
                new Short[] {(short) 2, (short) 1}, 180, 120, "cor_9123456789012345");

        var first = runtime.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)",
                String.class, new byte[][] {nonceV2, nonceV1}, new Short[] {(short) 2, (short) 1}, "RESOURCE",
                "dutch-development", "dutch-mobile", new byte[][] {thumbV2, thumbV1}, "GET",
                new byte[][] {targetV2, targetV1}, new byte[][] {bytes(99), bytes(100)},
                new Short[] {(short) 2, (short) 1}, 180, "cor_A123456789012345");
        var freshJtiReuse = runtime.queryForObject(
                "select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                new byte[][] {nonceV2, nonceV1}, new Short[] {(short) 2, (short) 1}, "RESOURCE",
                "dutch-development", "dutch-mobile", new byte[][] {thumbV2, thumbV1}, "GET",
                new byte[][] {targetV2, targetV1}, new byte[][] {bytes(101), bytes(102)},
                new Short[] {(short) 2, (short) 1}, 180, "cor_B123456789012345");

        assertThat(issued.get("result")).isEqualTo("ISSUED");
        assertThat(first).isEqualTo("CONSUMED");
        assertThat(freshJtiReuse).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest in (?,?,?,?)",
                Integer.class, replayV1, replayV2, bytes(99), bytes(100))).isEqualTo(4);
    }

    @Test
    void replayAliasesRejectTheSameProofAfterWriteKeyRotation() {
        var first = runtime.queryForObject("select claim_dpop_resource_replay(?,?,?)", Boolean.class,
                new byte[][] {bytes(111), bytes(112)}, new Short[] {(short) 2, (short) 1}, 180);
        var rotated = runtime.queryForObject("select claim_dpop_resource_replay(?,?,?)", Boolean.class,
                new byte[][] {bytes(113), bytes(111), bytes(112)},
                new Short[] {(short) 3, (short) 2, (short) 1}, 180);

        assertThat(first).isTrue();
        assertThat(rotated).isFalse();
    }

    @Test
    void removedDigestKeyCannotConsumeAnOldNonceAndLeavesItIssued() {
        var oldNonce = bytes(121);
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_7123456789012345678901", oldNonce, (short) 1, "RESOURCE", "dutch-development",
                "dutch-mobile", bytes(122), "GET", bytes(123), digests(bytes(124)), versions((short) 1), 180,
                120, "cor_C123456789012345");

        var removed = runtime.queryForObject("select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)",
                String.class, digests(bytes(125)), versions((short) 2), "RESOURCE", "dutch-development",
                "dutch-mobile", digests(bytes(126)), "GET", digests(bytes(127)), digests(bytes(128)),
                versions((short) 2), 180, "cor_D123456789012345");

        assertThat(removed).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select status from dpop_nonce where digest=?", String.class, oldNonce))
                .isEqualTo("ISSUED");
    }

    @Test
    void cleanupBoundsTerminalNonceHistoryWithinTheSingleBatchBudget() {
        while (runtime.queryForObject("select cleanup_expired_dpop_state(?)", Integer.class, 100) > 0) {
            // Clear prior test expiry state through the only authorized maintenance boundary.
        }
        for (int index = 131; index < 133; index++) {
            owner.update("insert into dpop_nonce(nonce_id,digest,digest_key_version,purpose,app_registration_id,"
                    + "client_id,proof_key_thumbprint_digest,method,target_digest,status,expires_at,created_at,"
                    + "correlation_id) values(?,?,1,'RESOURCE','dutch-development','dutch-mobile',?,'GET',?,"
                    + "'EXPIRED',transaction_timestamp()-interval '1 minute',"
                    + "transaction_timestamp()-interval '2 minutes',?)",
                    "dpn_" + index + "34567890123456789012", bytes(index), bytes(index + 10), bytes(index + 20),
                    "cor_" + index + "34567890123456");
        }

        assertThat(runtime.queryForObject("select cleanup_expired_dpop_state(?)", Integer.class, 1)).isOne();
        assertThat(owner.queryForObject("select count(*) from dpop_nonce where digest in (?,?)", Integer.class,
                bytes(131), bytes(132))).isOne();
    }

    @Test
    void signerDeadlineRollsBackTheRealNonceAndReplayTransaction() {
        var nonce = bytes(141);
        var thumbprint = bytes(142);
        var target = bytes(143);
        var replay = bytes(144);
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_8123456789012345678901", nonce, (short) 1, "TOKEN", "dutch-development",
                "dutch-mobile", thumbprint, "POST", target, digests(bytes(145)), versions((short) 1), 180,
                120, "cor_E123456789012345");
        var dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD);
        var transactions = new org.springframework.transaction.support.TransactionTemplate(
                new org.springframework.jdbc.datasource.DataSourceTransactionManager(dataSource));
        var isolated = new JdbcTemplate(dataSource);
        dev.distracted.iam.dpop.TokenAccessIssuer blocking = (authorization, subject, securityVersion,
                proofThumbprint, correlation, registration) -> {
                    try {
                        Thread.sleep(10_000);
                        return "unreachable";
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("interrupted");
                    }
                };
        try (var deadline = new dev.distracted.iam.dpop.DeadlineTokenAccessIssuer(
                blocking, java.time.Duration.ofMillis(25), 1, 1)) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
                assertThat(isolated.queryForObject(
                        "select consume_dpop_nonce_and_claim_replay(?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                        digests(nonce), versions((short) 1), "TOKEN", "dutch-development", "dutch-mobile",
                        digests(thumbprint), "POST", digests(target), digests(replay), versions((short) 1), 180,
                        "cor_F123456789012345")).isEqualTo("CONSUMED");
                deadline.issue(null, null, 1, null, "cor_F123456789012345", null);
            })).isInstanceOf(IllegalStateException.class).hasMessage("token_signing_unavailable");
        }
        assertThat(owner.queryForObject("select status from dpop_nonce where digest=?", String.class, nonce))
                .isEqualTo("ISSUED");
        assertThat(owner.queryForObject("select count(*) from dpop_replay where replay_digest=?",
                Integer.class, replay)).isZero();
    }

    @Test
    void issuingUnderARotatedWriteKeySupersedesThePriorLiveBinding() {
        var oldThumbprint = bytes(211);
        var oldTarget = bytes(212);
        var newThumbprint = bytes(213);
        var newTarget = bytes(214);
        var oldNonce = bytes(215);
        var newNonce = bytes(217);
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_a123456789012345678901", oldNonce, (short) 1, "RESOURCE", "dutch-development",
                "dutch-mobile", oldThumbprint, "GET", oldTarget, digests(bytes(216)), versions((short) 1),
                180, 120, "cor_J123456789012345", digests(oldThumbprint), digests(oldTarget));
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_b123456789012345678901", newNonce, (short) 2, "RESOURCE", "dutch-development",
                "dutch-mobile", newThumbprint, "GET", newTarget, digests(bytes(218)), versions((short) 2),
                180, 120, "cor_K123456789012345",
                digests(newThumbprint, oldThumbprint), digests(newTarget, oldTarget));

        assertThat(owner.queryForObject("select status from dpop_nonce where digest=?", String.class, oldNonce))
                .isEqualTo("SUPERSEDED");
        assertThat(owner.queryForObject("select status from dpop_nonce where digest=?", String.class, newNonce))
                .isEqualTo("ISSUED");
    }

    @Test
    void theJdbcStoreConsumesAResourceNonceOnlyUnderTheResourcePurpose() {
        var nonce = bytes(201);
        var thumbprint = bytes(202);
        var target = bytes(203);
        runtime.queryForMap("select * from issue_dpop_nonce(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "dpn_9123456789012345678901", nonce, (short) 1, "RESOURCE", "dutch-development",
                "dutch-mobile", thumbprint, "GET", target, digests(bytes(204), bytes(205)),
                versions((short) 2, (short) 1), 120, 180, "cor_G123456789012345");

        var store = new dev.distracted.iam.dpop.adapter.jdbc.JdbcDpopStateStore(runtime);
        var retry = new DpopIssuanceState(candidates((short) 1, nonce),
                candidates((short) 2, bytes(206), (short) 1, bytes(207)),
                candidates((short) 1, thumbprint), candidates((short) 1, target),
                "dutch-development", "dutch-mobile", "GET", 180, "cor_H123456789012345");
        var freshJti = new DpopIssuanceState(candidates((short) 1, nonce),
                candidates((short) 2, bytes(208), (short) 1, bytes(209)),
                candidates((short) 1, thumbprint), candidates((short) 1, target),
                "dutch-development", "dutch-mobile", "GET", 180, "cor_I123456789012345");

        assertThat(store.consumeResource(retry)).isTrue();
        assertThat(store.consumeResource(freshJti)).isFalse();
    }

    private static ProtectedDpopCandidates candidates(Object... alternating) {
        var values = new java.util.ArrayList<ProtectedDpopState>();
        for (int index = 0; index < alternating.length; index += 2) {
            values.add(new ProtectedDpopState((short) alternating[index], (byte[]) alternating[index + 1]));
        }
        return new ProtectedDpopCandidates(values);
    }

    private static byte[] bytes(int seed) {
        var value = new byte[32];
        java.util.Arrays.fill(value, (byte) seed);
        return value;
    }

    private static byte[][] digests(byte[]... values) { return values; }
    private static Short[] versions(short... values) {
        var boxed = new Short[values.length];
        for (int index = 0; index < values.length; index++) boxed[index] = values[index];
        return boxed;
    }
}
