package dev.distracted.iam.activation;

import java.util.Objects;

public final class AppSubjectResolver {
    private final AppSubjectRepository repository;
    private final AppSubjectMaterialGenerator materials;
    private final int maximumAttempts;

    public AppSubjectResolver(AppSubjectRepository repository, AppSubjectMaterialGenerator materials,
            int maximumAttempts) {
        this.repository = Objects.requireNonNull(repository);
        this.materials = Objects.requireNonNull(materials);
        if (maximumAttempts < 1 || maximumAttempts > 10) {
            throw new IllegalArgumentException("maximum attempts is invalid");
        }
        this.maximumAttempts = maximumAttempts;
    }

    public AppSubjectResolution resolve(AppSubjectResolutionCommand command) {
        Objects.requireNonNull(command, "command is required");
        for (int attempt = 0; attempt < maximumAttempts; attempt++) {
            var candidate = materials.nextSubject();
            var result = repository.resolve(command.appRegistrationId(), command.identity().identityId(),
                    candidate, materials.nextAuditId(), command.correlationId().value());
            if (result.outcome() == AppSubjectRepository.Outcome.CREATED
                    || result.outcome() == AppSubjectRepository.Outcome.EXISTING) {
                var outcome = result.outcome() == AppSubjectRepository.Outcome.CREATED
                        ? AppSubjectResolution.Outcome.CREATED : AppSubjectResolution.Outcome.EXISTING;
                return new AppSubjectResolution(result.appSubject(), outcome);
            }
            if (result.outcome() != AppSubjectRepository.Outcome.RETRY_COLLISION) {
                throw new AppSubjectResolutionException();
            }
        }
        throw new AppSubjectResolutionException();
    }
}
