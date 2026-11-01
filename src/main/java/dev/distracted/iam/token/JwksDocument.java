package dev.distracted.iam.token;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Collections;
import java.util.Map;

public record JwksDocument(List<Map<String, String>> keys) {
    public JwksDocument {
        keys = keys.stream().map(value -> Collections.unmodifiableMap(new LinkedHashMap<>(value))).toList();
    }
}
