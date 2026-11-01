package dev.distracted.iam.messaging;

import java.time.Instant;

public record AuditFact(String auditId, String factType, String subjectKind, String subjectId,
        String outcome, CorrelationId correlationId, CausationId causationId, String eventId,
        String reasonCode, Instant occurredAt) {
    public AuditFact {
        if (!auditId.matches("^aud_[A-Za-z0-9_-]{16,128}$")
                || correlationId == null || occurredAt == null
                || (eventId != null && !eventId.matches("^evt_[A-Za-z0-9_-]{16,128}$"))
                || !validSemantics(factType, subjectKind, subjectId, outcome, eventId, reasonCode)) {
            throw new IllegalArgumentException("audit identity is invalid");
        }
    }

    private static boolean validSemantics(String factType, String subjectKind, String subjectId,
            String outcome, String eventId, String reasonCode) {
        if ("EVENT".equals(subjectKind) && eventId != null && eventId.equals(subjectId)) {
            return "OUTBOX_EVENT_RECORDED".equals(factType) && "SUCCEEDED".equals(outcome) && reasonCode == null
                    || "OUTBOX_DELIVERY_QUARANTINED".equals(factType) && "FAILED".equals(outcome)
                    && ("RETRY_EXHAUSTED".equals(reasonCode) || "NON_RETRYABLE_FAILURE".equals(reasonCode));
        }
        return eventId == null && reasonCode == null && "SUCCEEDED".equals(outcome) && switch (factType) {
            case "IDENTITY_CREATED" -> "IDENTITY".equals(subjectKind) && matches(subjectId, "hid_");
            case "IDENTIFIER_CHALLENGE_ISSUED", "IDENTIFIER_CHALLENGE_SUPERSEDED",
                    "IDENTIFIER_CHALLENGE_LOCKED" ->
                "VERIFICATION_CHALLENGE".equals(subjectKind) && matches(subjectId, "vch_");
            case "IDENTIFIER_VERIFIED" -> "VERIFIED_IDENTIFIER".equals(subjectKind) && matches(subjectId, "vid_");
            default -> false;
        };
    }

    private static boolean matches(String value, String prefix) {
        return value != null && value.matches("^" + prefix + "[A-Za-z0-9_-]{22,128}$");
    }
}
