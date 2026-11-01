package dev.distracted.iam.messaging.snapshot;

import java.util.List;

public record OnboardingSnapshotPage(String appRegistrationId, List<OnboardingSnapshotItem> items,
                                     @com.fasterxml.jackson.annotation.JsonInclude(
                                             com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
                                     String nextCursor, boolean hasMore) {
    public OnboardingSnapshotPage {
        if (appRegistrationId == null || items == null || items.size() > 200
                || (hasMore && (nextCursor == null || nextCursor.isBlank()))
                || (!hasMore && nextCursor != null)) {
            throw new IllegalArgumentException("onboarding_snapshot_page_invalid");
        }
        items = List.copyOf(items);
    }
}
