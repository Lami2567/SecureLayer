package com.securelayer.core.api;

import java.util.Map;
import java.util.UUID;

public record PolicyResponse(UUID id, String name, int version, Map<String, Object> document) {
}
