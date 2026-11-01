package dev.distracted.iam.messaging.snapshot.adapter.jdbc;

import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotItem;
import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotPage;
import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotQuery;
import dev.distracted.iam.messaging.snapshot.SnapshotCursor;
import java.util.ArrayList;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcOnboardingSnapshotQuery implements OnboardingSnapshotQuery {
    private final JdbcTemplate jdbc;
    private final SnapshotCursor cursor = new SnapshotCursor();

    public JdbcOnboardingSnapshotQuery(JdbcTemplate jdbc) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc);
    }

    @Override public OnboardingSnapshotPage page(String appRegistrationId, String cursorValue, int limit) {
        if (appRegistrationId == null || limit < 1 || limit > 200) {
            throw new IllegalArgumentException("snapshot_request_invalid");
        }
        var after = cursorValue == null ? null : cursor.decode(cursorValue);
        try {
            var items = new ArrayList<>(jdbc.query(
                    "select * from read_onboarding_snapshot(?,?,?)",
                    (row, index) -> new OnboardingSnapshotItem(row.getString("app_subject"),
                            row.getString("activation_id"), row.getString("activation_state"),
                            row.getLong("activation_version"), row.getString("onboarding_reason"),
                            row.getLong("onboarding_version"), row.getString("required_profile_state")),
                    appRegistrationId, after, limit + 1));
            var hasMore = items.size() > limit;
            if (hasMore) items = new ArrayList<>(items.subList(0, limit));
            var next = hasMore ? cursor.encode(items.get(items.size() - 1).appSubject()) : null;
            return new OnboardingSnapshotPage(appRegistrationId, items, next, hasMore);
        } catch (DataAccessException exception) {
            throw new IllegalStateException("onboarding_snapshot_unavailable", exception);
        }
    }
}
