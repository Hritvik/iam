package dev.distracted.iam.dpop;

import java.util.List;

public record ProtectedDpopCandidates(List<ProtectedDpopState> values) {
    public ProtectedDpopCandidates {
        values = values == null ? List.of() : List.copyOf(values);
        if (values.isEmpty() || values.size() > 8
                || values.stream().map(ProtectedDpopState::keyVersion).distinct().count() != values.size()) {
            throw new IllegalArgumentException("dpop_state_candidates_invalid");
        }
    }
    public Short[] versions() { return values.stream().map(ProtectedDpopState::keyVersion).toArray(Short[]::new); }
    public byte[][] digests() { return values.stream().map(ProtectedDpopState::digest).toArray(byte[][]::new); }
    @Override public String toString() { return "ProtectedDpopCandidates[redacted]"; }
}
