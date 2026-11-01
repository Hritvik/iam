package dev.distracted.iam.registration;

import java.io.IOException;

public final class ClasspathPinnedRegistrationSource implements PinnedRegistrationSource {
    static final String IDENTITY = "contracts/manifest/dutch-development.app-registration.json";
    private static final String RESOURCE = "/canonical-contracts/manifest/dutch-development.app-registration.json";
    private static final int MAX_BYTES = 32_768;

    @Override
    public PinnedRegistrationDocument load() {
        try (var input = ClasspathPinnedRegistrationSource.class.getResourceAsStream(RESOURCE)) {
            if (input == null) throw new RegistrationException("registration_source_missing");
            var bytes = input.readNBytes(MAX_BYTES + 1);
            if (bytes.length > MAX_BYTES) throw new RegistrationException("registration_source_oversize");
            return new PinnedRegistrationDocument(IDENTITY, bytes);
        } catch (IOException exception) {
            throw new RegistrationException("registration_source_unavailable", exception);
        }
    }
}
