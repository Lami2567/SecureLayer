package com.securelayer.core.crypto;

public record KeyRotationResult(KeyMaterialRef previousKey, KeyMaterialRef activeKey) {
}
