package com.imom.crypto.api;

import java.util.Map;

/**
 * Response object of CryptoService
 */
public class CryptoResponse {

    private Map<String, String> responseMap;
    private int responseCode;

    public Map<String, String> getResponseMap() {
        return responseMap;
    }

    public void setResponseMap(Map<String, String> responseMap) {
        this.responseMap = responseMap;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

}
