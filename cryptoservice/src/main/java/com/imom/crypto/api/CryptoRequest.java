package com.imom.crypto.api;

import java.util.Map;

/**
 * Request object of CryptoService
 */

public class CryptoRequest {

    private Map<String, String> requestMap;

    private String tenantId;

    public Map<String, String> getRequestMap() {
        return requestMap;
    }

    public void setRequestMap(Map<String, String> requestMap) {
        this.requestMap = requestMap;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

}
