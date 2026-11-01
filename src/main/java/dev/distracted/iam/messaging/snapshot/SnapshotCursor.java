package dev.distracted.iam.messaging.snapshot;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class SnapshotCursor {
    private static final java.util.regex.Pattern SUBJECT = java.util.regex.Pattern.compile("^aps_[A-Za-z0-9_-]{24}$");

    public String encode(String appSubject) {
        if (appSubject == null || !SUBJECT.matcher(appSubject).matches()) {
            throw new IllegalArgumentException("snapshot_cursor_invalid");
        }
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(appSubject.getBytes(StandardCharsets.US_ASCII));
    }

    public String decode(String cursor) {
        if (cursor == null || cursor.isEmpty() || cursor.length() > 512
                || !cursor.matches("^[A-Za-z0-9_-]+$")) {
            throw new IllegalArgumentException("snapshot_cursor_invalid");
        }
        try {
            var value = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.US_ASCII);
            if (!SUBJECT.matcher(value).matches()) throw new IllegalArgumentException("snapshot_cursor_invalid");
            return value;
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("snapshot_cursor_invalid");
        }
    }
}
