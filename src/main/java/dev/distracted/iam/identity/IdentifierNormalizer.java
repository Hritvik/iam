package dev.distracted.iam.identity;

import com.ibm.icu.text.IDNA;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

public final class IdentifierNormalizer {
    private static final Pattern LOCAL = Pattern.compile("[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~]+(?:\\.[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~]+)*");
    private static final Pattern PHONE = Pattern.compile("\\+[1-9][0-9]{1,14}");
    private static final IDNA UTS46 = IDNA.getUTS46Instance(IDNA.USE_STD3_RULES | IDNA.CHECK_BIDI
            | IDNA.CHECK_CONTEXTJ | IDNA.NONTRANSITIONAL_TO_ASCII);

    public NormalizedIdentifier normalize(IdentifierType type, String submitted) {
        if (type == null || submitted == null) throw new IdentifierInvalidException();
        if (submitted.length() > 1024 || submitted.getBytes(StandardCharsets.UTF_8).length > 2048) {
            throw new IdentifierInvalidException();
        }
        var display = trimAsciiBoundary(submitted);
        if (display.codePoints().anyMatch(cp -> Character.isISOControl(cp))) throw new IdentifierInvalidException();
        return switch (type) {
            case EMAIL -> normalizeEmail(display);
            case PHONE -> normalizePhone(display);
        };
    }

    private static NormalizedIdentifier normalizeEmail(String display) {
        var separator = display.indexOf('@');
        if (separator <= 0 || separator != display.lastIndexOf('@') || separator == display.length() - 1) {
            throw new IdentifierInvalidException();
        }
        var local = display.substring(0, separator);
        var domain = display.substring(separator + 1);
        if (!LOCAL.matcher(local).matches() || local.getBytes(StandardCharsets.US_ASCII).length > 64
                || !StandardCharsets.US_ASCII.newEncoder().canEncode(local) || domain.endsWith(".")
                || domain.startsWith("[") || domain.endsWith("]")) throw new IdentifierInvalidException();
        var info = new IDNA.Info();
        var output = new StringBuilder();
        UTS46.nameToASCII(domain, output, info);
        var asciiDomain = output.toString().toLowerCase(Locale.ROOT);
        if (info.hasErrors() || asciiDomain.isBlank() || asciiDomain.split("\\.", -1).length == 0
                || java.util.Arrays.stream(asciiDomain.split("\\.", -1)).anyMatch(label -> label.isEmpty() || label.length() > 63)) {
            throw new IdentifierInvalidException();
        }
        var canonical = local + "@" + asciiDomain;
        if (canonical.getBytes(StandardCharsets.US_ASCII).length > 254) throw new IdentifierInvalidException();
        return new NormalizedIdentifier(IdentifierType.EMAIL, (short) 1, canonical, display);
    }

    private static NormalizedIdentifier normalizePhone(String display) {
        if (!PHONE.matcher(display).matches()) throw new IdentifierInvalidException();
        return new NormalizedIdentifier(IdentifierType.PHONE, (short) 1, display, display);
    }

    private static String trimAsciiBoundary(String value) {
        int start = 0, end = value.length();
        while (start < end && isAsciiWhitespace(value.charAt(start))) start++;
        while (end > start && isAsciiWhitespace(value.charAt(end - 1))) end--;
        return value.substring(start, end);
    }

    private static boolean isAsciiWhitespace(char character) {
        return character == 0x20 || character >= 0x09 && character <= 0x0d;
    }
}
