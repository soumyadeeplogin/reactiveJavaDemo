package com.imom.crypto.api;

/**
 * Enum for all response codes of CryptoService
 */
public enum CryptoResponseCode {

    CRYPTO_ERROR(-1), CRYPTO_SUCCESS(0), CRYPTO_KEY_NOT_FOUND(-2);

    private final int value;

    CryptoResponseCode(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }


}
