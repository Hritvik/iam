package dev.distracted.iam.authorization;

import dev.distracted.iam.platform.crypto.StartupCheckedCapability;
import java.util.Map;
import java.util.Set;

public interface AuthorizationCodeDigestCapability extends StartupCheckedCapability {
    ProtectedAuthorizationCode protect(String authorizationCodeId, byte[] secret);
    boolean matches(String authorizationCodeId, byte[] secret, short keyVersion, byte[] expectedDigest);
    short keyVersion();
    Set<Short> readableKeyVersions();
    Map<Short, String> keyReferences();
}
