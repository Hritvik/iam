package dev.distracted.iam.platform.crypto;

import java.util.regex.Pattern;

public record CapabilitySelfCheck(boolean healthy, String code) {
    private static final Pattern CODE = Pattern.compile("[a-z][a-z0-9_]{1,63}");

    public CapabilitySelfCheck {
        if (code == null || !CODE.matcher(code).matches()) {
            throw new IllegalArgumentException("self-check code is missing or outside its bounded format");
        }
    }

    public static CapabilitySelfCheck ready() {
        return new CapabilitySelfCheck(true, "capability_ready");
    }

    public static CapabilitySelfCheck unhealthy(String code) {
        return new CapabilitySelfCheck(false, code);
    }
}

