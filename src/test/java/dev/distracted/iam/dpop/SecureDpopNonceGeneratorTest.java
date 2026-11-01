package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashSet;
import org.junit.jupiter.api.Test;

class SecureDpopNonceGeneratorTest {
    @Test void generatesCanonicalHighEntropySingleUseMaterial() {
        var generator = new SecureDpopNonceGenerator();
        var values = new HashSet<String>();
        for (int index = 0; index < 128; index++) {
            var material = generator.next();
            assertThat(material.nonceId()).matches("^dpn_[A-Za-z0-9_-]{22}$");
            assertThat(material.rawNonce()).matches("^[A-Za-z0-9_-]{43}$");
            assertThat(values.add(material.rawNonce())).isTrue();
            assertThat(material.toString()).doesNotContain(material.rawNonce());
        }
    }

    @Test void materialRejectsMalformedValues() {
        assertThatThrownBy(() -> new DpopNonceMaterial("bad", "bad"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopNonceMaterial("dpn_" + "a".repeat(22), "bad"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopNonceMaterial(null, "a".repeat(43)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopNonceMaterial("dpn_" + "a".repeat(22), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ProtectedDpopState((short) 0, new byte[32]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ProtectedDpopState((short) 1, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ProtectedDpopState((short) 1, new byte[31]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
