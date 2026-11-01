package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.messaging.CorrelationId;
import java.util.ArrayDeque;
import java.util.List;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class AppSubjectResolverTest {
    private static final String IDENTITY = "hid_0123456789abcdefghijkl";
    private static final CorrelationId CORRELATION =
            new CorrelationId("cor_0123456789abcdefghijkl");

    @Test
    void resolvesAnOpaqueSubjectAndReturnsNoIdentity() {
        var repository = new RecordingRepository(AppSubjectRepository.Outcome.CREATED);
        var resolver = new AppSubjectResolver(repository,
                new SequenceGenerator(List.of("aps_AAAAAAAAAAAAAAAAAAAAAAAA")), 3);

        var result = resolver.resolve(command());

        assertThat(result.appSubject().value()).isEqualTo("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        assertThat(result.outcome()).isEqualTo(AppSubjectResolution.Outcome.CREATED);
        assertThat(result.toString()).doesNotContain(IDENTITY).doesNotContain(result.appSubject().value());
    }

    @Test
    void retriesACollisionWithFreshMaterial() {
        var repository = new RecordingRepository(
                AppSubjectRepository.Outcome.RETRY_COLLISION,
                AppSubjectRepository.Outcome.CREATED);
        var resolver = new AppSubjectResolver(repository, new SequenceGenerator(List.of(
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aps_BBBBBBBBBBBBBBBBBBBBBBBB")), 3);

        var result = resolver.resolve(command());

        assertThat(result.appSubject().value()).isEqualTo("aps_BBBBBBBBBBBBBBBBBBBBBBBB");
        assertThat(repository.candidates).containsExactly(
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aps_BBBBBBBBBBBBBBBBBBBBBBBB");
    }

    @Test
    void collisionExhaustionIsNonRevealing() {
        var repository = new RecordingRepository(AppSubjectRepository.Outcome.RETRY_COLLISION,
                AppSubjectRepository.Outcome.RETRY_COLLISION, AppSubjectRepository.Outcome.RETRY_COLLISION);
        var resolver = new AppSubjectResolver(repository, new SequenceGenerator(List.of(
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aps_BBBBBBBBBBBBBBBBBBBBBBBB",
                "aps_CCCCCCCCCCCCCCCCCCCCCCCC")), 3);

        assertThatThrownBy(() -> resolver.resolve(command()))
                .isInstanceOf(AppSubjectResolutionException.class)
                .hasMessage("app_subject_resolution_failed")
                .hasMessageNotContaining(IDENTITY);
    }

    @Test
    void existingMappingIsReturnedAndRejectedOutcomeIsClosed() {
        var existingRepository = new RecordingRepository(AppSubjectRepository.Outcome.EXISTING) {
            @Override public Result resolve(String appId, String identityId, AppSubject candidate,
                    String auditId, String correlationId) {
                return new Result(Outcome.EXISTING, new AppSubject("aps_ZZZZZZZZZZZZZZZZZZZZZZZZ"));
            }
        };
        var existing = new AppSubjectResolver(existingRepository,
                new SequenceGenerator(List.of("aps_AAAAAAAAAAAAAAAAAAAAAAAA")), 3).resolve(command());
        var rejected = new AppSubjectResolver(
                new RecordingRepository(AppSubjectRepository.Outcome.REJECTED),
                new SequenceGenerator(List.of("aps_AAAAAAAAAAAAAAAAAAAAAAAA")), 3);

        assertThat(existing.outcome()).isEqualTo(AppSubjectResolution.Outcome.EXISTING);
        assertThat(existing.appSubject().value()).isEqualTo("aps_ZZZZZZZZZZZZZZZZZZZZZZZZ");
        assertThatThrownBy(() -> rejected.resolve(command()))
                .isInstanceOf(AppSubjectResolutionException.class)
                .hasMessage("app_subject_resolution_failed");
    }

    @Test
    void constructorsRejectMissingOrUnsafeInputs() {
        assertThatThrownBy(() -> new AppSubjectResolutionCommand(null,
                new IdentityReference(IDENTITY), CORRELATION)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolutionCommand("BAD",
                new IdentityReference(IDENTITY), CORRELATION)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolutionCommand("dutch-development", null, CORRELATION))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolutionCommand("dutch-development",
                new IdentityReference(null), CORRELATION)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolutionCommand("dutch-development",
                new IdentityReference(IDENTITY), null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolver(new RecordingRepository(),
                new SequenceGenerator(List.of()), 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolver(new RecordingRepository(),
                new SequenceGenerator(List.of()), 11)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AppSubjectResolution(null, AppSubjectResolution.Outcome.CREATED))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AppSubjectResolution(
                new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA"), null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void subjectRequiresTheExactPublicShape() {
        assertThatThrownBy(() -> new AppSubject("aps_short"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("app subject is invalid");
    }

    @Test
    void productionGeneratorEncodesExactlyEighteenFreshBytesWithoutPadding() {
        var random = new SecureRandom() {
            @Override public void nextBytes(byte[] bytes) {
                assertThat(bytes).hasSize(18);
                java.util.Arrays.fill(bytes, (byte) 0xff);
            }
        };

        var subject = new SecureAppSubjectMaterialGenerator(random).nextSubject();

        assertThat(subject.value()).isEqualTo("aps_________________________");
        assertThat(subject.value()).hasSize(28).doesNotContain("=");
    }

    private static AppSubjectResolutionCommand command() {
        return new AppSubjectResolutionCommand("dutch-development", new IdentityReference(IDENTITY), CORRELATION);
    }

    private static final class SequenceGenerator implements AppSubjectMaterialGenerator {
        private final ArrayDeque<String> values;

        private SequenceGenerator(List<String> values) { this.values = new ArrayDeque<>(values); }

        @Override public AppSubject nextSubject() { return new AppSubject(values.remove()); }

        @Override public String nextAuditId() { return "aud_0123456789abcdefghijkl"; }
    }

    private static class RecordingRepository implements AppSubjectRepository {
        private final ArrayDeque<Outcome> outcomes;
        private final java.util.ArrayList<String> candidates = new java.util.ArrayList<>();

        private RecordingRepository(Outcome... outcomes) {
            this.outcomes = new ArrayDeque<>(List.of(outcomes));
        }

        @Override public Result resolve(String appId, String identityId, AppSubject candidate,
                String auditId, String correlationId) {
            candidates.add(candidate.value());
            var outcome = outcomes.remove();
            return new Result(outcome, outcome == Outcome.CREATED ? candidate : null);
        }
    }
}
