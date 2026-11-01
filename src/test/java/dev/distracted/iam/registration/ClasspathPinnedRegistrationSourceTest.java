package dev.distracted.iam.registration;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

class ClasspathPinnedRegistrationSourceTest {
    @Test
    void loadsTheCanonicalDutchManifestAsBoundedBytes() {
        var source = new ClasspathPinnedRegistrationSource();

        var document = source.load();

        assertThat(document.sourceIdentity()).isEqualTo("contracts/manifest/dutch-development.app-registration.json");
        assertThat(document.bytes()).asString().contains("\"appRegistrationId\": \"dutch-development\"");
    }

    @Test
    void packagedCanonicalInputsHaveSourceDigestParity() throws Exception {
        for (var path : new String[]{
                "manifest/dutch-development.app-registration.json",
                "manifest/app-registration.schema.json",
                "manifest/product-security-policy.schema.json",
                "conformance/semantic-requirements.yaml"}) {
            var source = Files.readAllBytes(Path.of("contracts").resolve(path));
            try (var packaged = getClass().getResourceAsStream("/canonical-contracts/" + path)) {
                assertThat(packaged).isNotNull();
                assertThat(MessageDigest.getInstance("SHA-256").digest(packaged.readAllBytes()))
                        .isEqualTo(MessageDigest.getInstance("SHA-256").digest(source));
            }
        }
    }
}
