package dev.distracted.iam.dpop;

import dev.distracted.iam.platform.crypto.StartupCheckedCapability;
import java.util.Map;
import java.util.Set;

public interface DpopStateDigestCapability extends StartupCheckedCapability {
    ProtectedDpopState protect(DpopStatePurpose purpose, String bindingId, byte[] transientValue);
    ProtectedDpopCandidates protectReadable(DpopStatePurpose purpose, String bindingId, byte[] transientValue);
    boolean matches(DpopStatePurpose purpose, String bindingId, byte[] transientValue,
                    short keyVersion, byte[] expectedDigest);
    short keyVersion();
    Set<Short> readableKeyVersions();
    Map<Short, String> keyReferences();
}
