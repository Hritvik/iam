package dev.distracted.iam.authorization.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class SecureRefreshTokenMaterialGeneratorTest {
    private final RefreshTokenMaterialGenerator generator =
            new SecureRefreshTokenMaterialGenerator(new SecureRandom());

    @Test
    void generatesOpaqueUniqueMaterialAndDigestsTheRawToken() throws Exception {
        var first = generator.newFamily();
        var second = generator.newFamily();

        assertThat(first.familyId()).matches("^rfm_[A-Za-z0-9_-]{22,128}$");
        assertThat(first.tokenId()).matches("^rft_[A-Za-z0-9_-]{22,128}$");
        assertThat(first.rawToken()).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(first.digest()).hasSize(32);
        assertThat(second.familyId()).isNotEqualTo(first.familyId());
        assertThat(second.digest()).isNotEqualTo(first.digest());
        assertThat(first.digest()).isEqualTo(
                MessageDigest.getInstance("SHA-256").digest(first.rawToken().getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void rotatesWithinTheSameFamilyWithFreshMaterial() {
        var first = generator.newFamily();
        var rotated = generator.rotate(first.familyId());

        assertThat(rotated.familyId()).isEqualTo(first.familyId());
        assertThat(rotated.tokenId()).isNotEqualTo(first.tokenId());
        assertThat(rotated.rawToken()).isNotEqualTo(first.rawToken());
        assertThat(rotated.digest()).isNotEqualTo(first.digest());
    }
}
