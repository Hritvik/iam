package dev.distracted.iam.identity;

import dev.distracted.iam.messaging.AuditFact;
import dev.distracted.iam.messaging.CorrelationId;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import dev.distracted.iam.platform.crypto.SealedIdentifierValue;
import dev.distracted.iam.platform.crypto.StructuredIdentifierEncryptionCapability;
import dev.distracted.iam.platform.crypto.VersionedBlindIndexCapability;
import dev.distracted.iam.platform.persistence.AuditFactRepository;
import dev.distracted.iam.platform.persistence.TransactionRunner;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class IdentityService {
    private final JdbcTemplate jdbc;
    private final TransactionRunner transactions;
    private final AuditFactRepository audits;
    private final IdentifierNormalizer normalizer;
    private final StructuredIdentifierEncryptionCapability encryption;
    private final VersionedBlindIndexCapability blindIndexes;
    private final ChallengeDigestCapability digests;
    private final IdentityMaterialGenerator materials;
    private final ChallengeDeliveryPort delivery;
    private final String environment;
    private final PromotionObserver promotionObserver;

    public IdentityService(JdbcTemplate jdbc, TransactionRunner transactions, AuditFactRepository audits,
            IdentifierNormalizer normalizer, StructuredIdentifierEncryptionCapability encryption,
            VersionedBlindIndexCapability blindIndexes, ChallengeDigestCapability digests,
            IdentityMaterialGenerator materials, ChallengeDeliveryPort delivery, String environment) {
        this(jdbc, transactions, audits, normalizer, encryption, blindIndexes, digests, materials, delivery,
                environment, PromotionObserver.NONE);
    }

    public IdentityService(JdbcTemplate jdbc, TransactionRunner transactions, AuditFactRepository audits,
            IdentifierNormalizer normalizer, StructuredIdentifierEncryptionCapability encryption,
            VersionedBlindIndexCapability blindIndexes, ChallengeDigestCapability digests,
            IdentityMaterialGenerator materials, ChallengeDeliveryPort delivery, String environment,
            PromotionObserver promotionObserver) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.audits = audits;
        this.normalizer = normalizer;
        this.encryption = encryption;
        this.blindIndexes = blindIndexes;
        this.digests = digests;
        this.materials = materials;
        this.delivery = delivery;
        this.environment = requireEnvironment(environment);
        this.promotionObserver = java.util.Objects.requireNonNull(promotionObserver, "promotionObserver");
    }

    public IdentityReference createIdentity(CorrelationId correlationId) {
        return transactions.required(() -> {
            var identityId = materials.identityId();
            var now = databaseNow();
            jdbc.update("insert into human_identity(identity_id,state,security_version,version,created_at,updated_at) values (?,?,?,?,?,?)",
                    identityId, "ACTIVE", 1L, 1L, Timestamp.from(now), Timestamp.from(now));
            audit("IDENTITY_CREATED", "IDENTITY", identityId, correlationId, now);
            return new IdentityReference(identityId);
        });
    }

    public String issue(String identityId, IdentifierType type, String submitted, Duration ttl, int maxAttempts,
            CorrelationId correlationId) {
        validateChallengePolicy(ttl, maxAttempts);
        var normalized = normalizer.normalize(type, submitted);
        var code = new SecretChallengeCode(materials.challengeCode());
        final String challengeId;
        try {
            challengeId = transactions.required(() -> issueLocked(identityId, type, normalized, ttl, maxAttempts,
                    correlationId, code, null, null));
        } catch (DataIntegrityViolationException exception) {
            throw new ChallengeConflictException();
        }
        delivery.deliver(challengeId, code);
        return challengeId;
    }

    public String resend(String currentChallengeId, String submitted, Duration ttl, int maxAttempts,
            CorrelationId correlationId) {
        validateChallengePolicy(ttl, maxAttempts);
        var code = new SecretChallengeCode(materials.challengeCode());
        final String replacement;
        try {
            replacement = transactions.required(() -> {
            var current = loadChallenge(currentChallengeId, false).orElseThrow(ChallengeRejectedException::new);
            lockIdentity(current.identityId());
            current = loadChallenge(currentChallengeId, true).orElseThrow(ChallengeRejectedException::new);
            if (!"ISSUED".equals(current.state())) throw new ChallengeRejectedException();
            var normalized = normalizer.normalize(current.type(), submitted);
            var expectedIndex = blindIndexes.deriveForVersion(current.blindIndexKeyVersion(), environment,
                    current.type(), normalized.normalizationVersion(), normalized.canonical());
            if (!MessageDigest.isEqual(expectedIndex, current.blindIndex())) throw new ChallengeRejectedException();
            var replacementId = materials.challengeId();
            var now = databaseNow();
            var changed = applied("select supersede_verification_challenge(?,?,?)", current.challengeId(),
                    current.version(), replacementId);
            if (changed != 1) throw new ChallengeConflictException();
            audit("IDENTIFIER_CHALLENGE_SUPERSEDED", "VERIFICATION_CHALLENGE", current.challengeId(), correlationId, now);
            return issueLocked(current.identityId(), current.type(), normalized, ttl, maxAttempts,
                    correlationId, code, current.challengeId(), replacementId);
            });
        } catch (DataIntegrityViolationException exception) {
            throw new ChallengeConflictException();
        }
        delivery.deliver(replacement, code);
        return replacement;
    }

    public VerificationResult verify(String challengeId, String suppliedCode, CorrelationId correlationId) {
        if (!validOpaqueId(challengeId, "vch_") || suppliedCode == null || suppliedCode.length() > 512
                || suppliedCode.getBytes(StandardCharsets.UTF_8).length > 1024) return VerificationResult.REJECTED;
        try {
            return transactions.required(() -> verifyLocked(challengeId, suppliedCode, correlationId));
        } catch (DataIntegrityViolationException exception) {
            return VerificationResult.CONFLICT;
        }
    }

    public Optional<IdentityReference> find(IdentifierType type, String submitted) {
        var normalized = normalizer.normalize(type, submitted);
        for (var entry : blindIndexes.deriveReadable(
                environment, type, normalized.normalizationVersion(), normalized.canonical()).entrySet()) {
            var rows = jdbc.query("select v.identity_id from verified_identifier v join verified_identifier_blind_index b "
                        + "on b.identifier_id=v.identifier_id where b.identifier_type=? and b.normalization_version=? "
                        + "and b.blind_index_key_version=? and b.blind_index=?",
                (result, row) -> new IdentityReference(result.getString(1)), type.name(),
                normalized.normalizationVersion(), entry.getKey(), entry.getValue());
            if (!rows.isEmpty()) return Optional.of(rows.getFirst());
        }
        return Optional.empty();
    }

    private String issueLocked(String identityId, IdentifierType type, NormalizedIdentifier normalized, Duration ttl,
            int maxAttempts, CorrelationId correlationId, SecretChallengeCode code, String challengeBeingReplaced,
            String suppliedChallengeId) {
        lockIdentity(identityId);
        if (challengeBeingReplaced == null && jdbc.queryForObject(
                "select count(*) from verified_identifier where identity_id=? and identifier_type=?", Integer.class,
                identityId, type.name()) != 0) throw new ChallengeRejectedException();
        var challengeId = suppliedChallengeId == null ? materials.challengeId() : suppliedChallengeId;
        var now = databaseNow();
        var expires = now.plus(ttl);
        var blindIndex = blindIndexes.derive(environment, type, normalized.normalizationVersion(), normalized.canonical());
        var canonical = seal(challengeId, "canonical", type, normalized.normalizationVersion(), normalized.canonical());
        var display = seal(challengeId, "display", type, normalized.normalizationVersion(), normalized.display());
        var digest = digests.digest(environment, challengeId, code.reveal());
        jdbc.update("insert into verification_challenge(challenge_id,identity_id,identifier_type,normalization_version,"
                        + "canonical_ciphertext,canonical_nonce,canonical_tag,display_ciphertext,display_nonce,display_tag,"
                        + "encryption_key_version,candidate_blind_index_key_version,candidate_blind_index,challenge_digest,"
                        + "digest_key_version,state,attempt_count,max_attempts,expires_at,version,created_at,updated_at) "
                        + "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'ISSUED',0,?,?,1,?,?)",
                challengeId, identityId, type.name(), normalized.normalizationVersion(), canonical.ciphertext(),
                canonical.nonce(), canonical.tag(), display.ciphertext(), display.nonce(), display.tag(),
                encryption.keyVersion(), blindIndexes.keyVersion(), blindIndex, digest, digests.keyVersion(), maxAttempts,
                Timestamp.from(expires), Timestamp.from(now), Timestamp.from(now));
        audit("IDENTIFIER_CHALLENGE_ISSUED", "VERIFICATION_CHALLENGE", challengeId, correlationId, now);
        return challengeId;
    }

    private VerificationResult verifyLocked(String challengeId, String suppliedCode, CorrelationId correlationId) {
        var challenge = loadChallenge(challengeId, false).orElse(null);
        if (challenge == null) return VerificationResult.REJECTED;
        lockIdentity(challenge.identityId());
        challenge = loadChallenge(challengeId, true).orElseThrow();
        if ("CONSUMED".equals(challenge.state())) return VerificationResult.REJECTED;
        if (!"ISSUED".equals(challenge.state())) return VerificationResult.REJECTED;
        var now = databaseNow();
        if (!now.isBefore(challenge.expiresAt())) {
            applied("select expire_verification_challenge(?,?)", challengeId, challenge.version());
            return VerificationResult.REJECTED;
        }
        var suppliedDigest = digests.digest(challenge.digestKeyVersion(), environment, challengeId, suppliedCode);
        if (!MessageDigest.isEqual(suppliedDigest, challenge.digest())) return wrongAttempt(challenge, correlationId, now);
        return consume(challenge, correlationId, now);
    }

    private VerificationResult wrongAttempt(Challenge challenge, CorrelationId correlationId, Instant now) {
        var next = challenge.attemptCount() + 1;
        var locked = next >= challenge.maxAttempts();
        var changed = applied("select fail_verification_challenge(?,?)", challenge.challengeId(), challenge.version());
        if (changed != 1) return VerificationResult.CONFLICT;
        if (locked) audit("IDENTIFIER_CHALLENGE_LOCKED", "VERIFICATION_CHALLENGE", challenge.challengeId(), correlationId, now);
        return VerificationResult.REJECTED;
    }

    private VerificationResult consume(Challenge challenge, CorrelationId correlationId, Instant now) {
        var identifierId = materials.identifierId();
        var canonicalPlain = encryption.open(challenge.canonical(), aad("verification_challenge", challenge.challengeId(),
                "canonical", challenge.type(), challenge.normalizationVersion(), challenge.encryptionKeyVersion()));
        var displayPlain = encryption.open(challenge.display(), aad("verification_challenge", challenge.challengeId(),
                "display", challenge.type(), challenge.normalizationVersion(), challenge.encryptionKeyVersion()));
        var canonical = encryption.seal(canonicalPlain, aad("verified_identifier", identifierId, "canonical",
                challenge.type(), challenge.normalizationVersion(), encryption.keyVersion()));
        var display = encryption.seal(displayPlain, aad("verified_identifier", identifierId, "display",
                challenge.type(), challenge.normalizationVersion(), encryption.keyVersion()));
        var changed = applied("select consume_verification_challenge(?,?)", challenge.challengeId(), challenge.version());
        if (changed != 1) return VerificationResult.CONFLICT;
        promotionObserver.after("challenge_consumed");
        jdbc.update("insert into verified_identifier(identifier_id,identity_id,identifier_type,normalization_version,"
                        + "canonical_ciphertext,canonical_nonce,canonical_tag,display_ciphertext,display_nonce,display_tag,"
                        + "encryption_key_version,verified_at,version,created_at,updated_at) values (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
                identifierId, challenge.identityId(), challenge.type().name(), challenge.normalizationVersion(),
                canonical.ciphertext(), canonical.nonce(), canonical.tag(), display.ciphertext(), display.nonce(), display.tag(),
                encryption.keyVersion(), Timestamp.from(now), Timestamp.from(now), Timestamp.from(now));
        promotionObserver.after("identifier_inserted");
        var indexes = new java.util.TreeMap<Short, byte[]>();
        indexes.put(challenge.blindIndexKeyVersion(), challenge.blindIndex());
        var canonicalValue = new String(canonicalPlain, StandardCharsets.UTF_8);
        for (var version : blindIndexes.requiredWriteKeyVersions()) {
            indexes.put(version, blindIndexes.deriveForVersion(version, environment, challenge.type(),
                    challenge.normalizationVersion(), canonicalValue));
        }
        indexes.forEach((version, index) -> {
            jdbc.update("insert into verified_identifier_blind_index(identifier_id,identifier_type,normalization_version,"
                            + "blind_index_key_version,blind_index) values (?,?,?,?,?)", identifierId,
                    challenge.type().name(), challenge.normalizationVersion(), version, index);
            promotionObserver.after("index_inserted_" + version);
        });
        promotionObserver.after("indexes_inserted");
        if (applied("select increment_identity_security(?,?)", challenge.identityId(),
                challenge.identityVersion()) != 1) {
            throw new ChallengeConflictException();
        }
        promotionObserver.after("identity_updated");
        audit("IDENTIFIER_VERIFIED", "VERIFIED_IDENTIFIER", identifierId, correlationId, now);
        promotionObserver.after("audit_inserted");
        return VerificationResult.VERIFIED;
    }

    private Optional<Challenge> loadChallenge(String challengeId, boolean lock) {
        if (lock) jdbc.queryForObject("select lock_verification_challenge(?)", Long.class, challengeId);
        var sql = "select c.*,i.version identity_version from verification_challenge c join human_identity i "
                + "on i.identity_id=c.identity_id where c.challenge_id=?";
        return jdbc.query(sql, (result, row) -> challenge(result), challengeId).stream().findFirst();
    }

    private static Challenge challenge(ResultSet result) throws SQLException {
        return new Challenge(result.getString("challenge_id"), result.getString("identity_id"),
                IdentifierType.valueOf(result.getString("identifier_type")), result.getShort("normalization_version"),
                sealed(result, "canonical"), sealed(result, "display"), result.getShort("encryption_key_version"),
                result.getShort("candidate_blind_index_key_version"), result.getBytes("candidate_blind_index"),
                result.getBytes("challenge_digest"), result.getShort("digest_key_version"), result.getString("state"),
                result.getInt("attempt_count"),
                result.getInt("max_attempts"), result.getTimestamp("expires_at").toInstant(), result.getLong("version"),
                result.getLong("identity_version"));
    }

    private static SealedIdentifierValue sealed(ResultSet result, String field) throws SQLException {
        return new SealedIdentifierValue(result.getBytes(field + "_ciphertext"), result.getBytes(field + "_nonce"),
                result.getBytes(field + "_tag"), result.getShort("encryption_key_version"));
    }

    private SealedIdentifierValue seal(String rowId, String field, IdentifierType type, short norm, String plaintext) {
        return encryption.seal(plaintext.getBytes(StandardCharsets.UTF_8),
                aad("verification_challenge", rowId, field, type, norm, encryption.keyVersion()));
    }
    private byte[] aad(String table, String rowId, String field, IdentifierType type, short norm, short keyVersion) {
        return IdentifierAad.forField(environment, table, rowId, field, type, norm, keyVersion);
    }
    private void lockIdentity(String identityId) {
        if (jdbc.queryForObject("select lock_human_identity(?)", Long.class, identityId) == null)
            throw new ChallengeRejectedException();
    }
    private Instant databaseNow() { return jdbc.queryForObject("select transaction_timestamp()", Timestamp.class).toInstant(); }
    private int applied(String sql, Object... parameters) {
        var result = jdbc.queryForObject(sql, Integer.class, parameters);
        return result == null ? 0 : result;
    }
    private void audit(String fact, String kind, String subject, CorrelationId correlation, Instant now) {
        audits.append(new AuditFact(materials.auditId(), fact, kind, subject, "SUCCEEDED", correlation, null, null, null, now));
    }
    private static void validateChallengePolicy(Duration ttl, int maxAttempts) {
        if (ttl == null || ttl.compareTo(Duration.ofSeconds(60)) < 0 || ttl.compareTo(Duration.ofHours(24)) > 0
                || maxAttempts < 1 || maxAttempts > 20) throw new IllegalArgumentException("challenge_policy_invalid");
    }
    private static String requireEnvironment(String environment) {
        if (!java.util.Set.of("development", "test", "staging", "production").contains(environment))
            throw new IllegalArgumentException("environment_invalid");
        return environment;
    }
    private static boolean validOpaqueId(String value, String prefix) {
        return value != null && value.length() <= 132 && value.matches("^" + prefix + "[A-Za-z0-9_-]{22,128}$");
    }
    private record Challenge(String challengeId, String identityId, IdentifierType type, short normalizationVersion,
            SealedIdentifierValue canonical, SealedIdentifierValue display, short encryptionKeyVersion,
            short blindIndexKeyVersion, byte[] blindIndex, byte[] digest, short digestKeyVersion,
            String state, int attemptCount,
            int maxAttempts, Instant expiresAt, long version, long identityVersion) {
        Challenge {
            blindIndex = blindIndex.clone();
            digest = digest.clone();
        }
        @Override public byte[] blindIndex() { return blindIndex.clone(); }
        @Override public byte[] digest() { return digest.clone(); }
        @Override public String toString() { return "Challenge[protected]"; }
    }
}
