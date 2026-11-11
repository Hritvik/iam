package dev.distracted.iam.authorization.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class RefreshValueObjectTest {
    private static final String FAMILY = "rfm_" + "a".repeat(24);
    private static final String TOKEN = "rft_" + "b".repeat(24);
    private static final String IDENTITY = "hid_abcdefghijklmnopqrstuv";
    private static final String APP = "dutch-development";
    private static final String CLIENT = "dutch-mobile";
    private static final String RESOURCE = "dutch-api";
    private static final String AUDIENCE = "https://api.dutch.invalid";
    private static final String SCOPE = "member:read";
    private static final String JKT = "a".repeat(43);
    private static final String CORRELATION = "cor_0123456789abcdef";
    private static final Duration ABSOLUTE = Duration.ofDays(30);
    private static final Duration IDLE = Duration.ofDays(7);
    private static final byte[] DIGEST = new byte[32];

    @Test
    void materialRejectsMalformedValuesAndKeepsTheTokenOutOfToString() {
        invalid(() -> new RefreshTokenMaterial(null, TOKEN, "a".repeat(43), DIGEST));
        invalid(() -> new RefreshTokenMaterial("bad", TOKEN, "a".repeat(43), DIGEST));
        invalid(() -> new RefreshTokenMaterial(FAMILY, null, "a".repeat(43), DIGEST));
        invalid(() -> new RefreshTokenMaterial(FAMILY, "bad", "a".repeat(43), DIGEST));
        invalid(() -> new RefreshTokenMaterial(FAMILY, TOKEN, null, DIGEST));
        invalid(() -> new RefreshTokenMaterial(FAMILY, TOKEN, "short", DIGEST));
        invalid(() -> new RefreshTokenMaterial(FAMILY, TOKEN, "a".repeat(43), null));
        invalid(() -> new RefreshTokenMaterial(FAMILY, TOKEN, "a".repeat(43), new byte[31]));

        var first = new RefreshTokenMaterial(FAMILY, TOKEN, "a".repeat(43), DIGEST);
        var second = new RefreshTokenMaterial(FAMILY, TOKEN, "a".repeat(43), DIGEST);
        assertThat(first).isEqualTo(second).hasSameHashCodeAs(second);
        assertThat(first.toString()).doesNotContain("a".repeat(43));
    }

    @Test
    void familyIssueRejectsMalformedValues() {
        invalid(() -> issue(null, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue("bad", TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, null, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, "bad", IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, null, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, " ", CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, " ", RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, " ", AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, " ", SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, " ", JKT, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, null, 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, "bad", 1, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 0, DIGEST,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, null,
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, new byte[31],
                ABSOLUTE, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                null, IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                Duration.ofHours(12), IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                Duration.ofDays(91), IDLE, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, null, CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, Duration.ofMinutes(30), CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, Duration.ofDays(31), CORRELATION));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, null));
        invalid(() -> issue(FAMILY, TOKEN, IDENTITY, APP, CLIENT, RESOURCE, AUDIENCE, SCOPE, JKT, 1, DIGEST,
                ABSOLUTE, IDLE, "bad"));
    }

    @Test
    void rotationCommandRejectsMalformedValues() {
        invalid(() -> command(null, DIGEST, JKT, 1, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(new byte[31], DIGEST, JKT, 1, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, null, JKT, 1, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, new byte[31], JKT, 1, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, DIGEST, null, 1, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, DIGEST, "bad", 1, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, DIGEST, JKT, 0, TOKEN, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, null, CORRELATION, IDLE));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, "bad", CORRELATION, IDLE));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, TOKEN, null, IDLE));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, TOKEN, "bad", IDLE));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, TOKEN, CORRELATION, null));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, TOKEN, CORRELATION, Duration.ofMinutes(30)));
        invalid(() -> command(DIGEST, DIGEST, JKT, 1, TOKEN, CORRELATION, Duration.ofDays(31)));
    }

    @Test
    void issueReceiptRejectsInconsistentTimes() {
        var now = Instant.parse("2026-11-09T00:00:00Z");
        invalid(() -> new RefreshIssueReceipt(null, now, now, 1));
        invalid(() -> new RefreshIssueReceipt(now, null, now, 1));
        invalid(() -> new RefreshIssueReceipt(now, now, null, 1));
        invalid(() -> new RefreshIssueReceipt(now, now.minusSeconds(1), now, 1));
        invalid(() -> new RefreshIssueReceipt(now, now, now.plusSeconds(1), 0));
    }

    private static RefreshFamilyIssue issue(String familyId, String tokenId, String identity, String app,
            String client, String resource, String audience, String scope, String jkt, long version,
            byte[] digest, Duration absolute, Duration idle, String correlation) {
        return new RefreshFamilyIssue(familyId, tokenId, identity, app, client, resource, audience, scope,
                jkt, version, digest, absolute, idle, correlation);
    }

    private static RefreshRotationCommand command(byte[] presented, byte[] next, String jkt, long version,
            String tokenId, String correlation, Duration idle) {
        return new RefreshRotationCommand(presented, next, jkt, version, tokenId, correlation, idle);
    }

    private static void invalid(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(IllegalArgumentException.class);
    }
}
