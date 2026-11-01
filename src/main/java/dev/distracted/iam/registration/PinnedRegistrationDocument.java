package dev.distracted.iam.registration;

import java.util.Arrays;
import java.util.Objects;

public final class PinnedRegistrationDocument {
    private final String sourceIdentity;
    private final byte[] bytes;

    public PinnedRegistrationDocument(String sourceIdentity, byte[] bytes) {
        this.sourceIdentity = Objects.requireNonNull(sourceIdentity);
        this.bytes = Arrays.copyOf(Objects.requireNonNull(bytes), bytes.length);
    }

    public String sourceIdentity() { return sourceIdentity; }

    public byte[] bytes() { return Arrays.copyOf(bytes, bytes.length); }
}
