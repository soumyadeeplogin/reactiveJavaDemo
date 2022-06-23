package com.imom.crypto.manager;

import java.util.Date;

public class KMSKeys {
    private String arn;
    private String keyId;
    private String sources;
    private String tenantId;
    private byte[] plaintextKey;
    private byte[] keyMaterial;
    private Date startDate;
    private String status;
    private String user;
    private String ipAddress;

    public byte[] getKeyMaterial() { return keyMaterial; }

    public void setKeyMaterial(byte[] keyMaterial) { this.keyMaterial = keyMaterial; }

    public String getIpAddress() { return ipAddress; }

    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getUser() { return user; }

    public void setUser(String user) { this.user = user; }

    public String getStatus() { return status; }

    public void setStatus(String status) { this.status = status; }

    public String getSources() {
        return sources;
    }

    public void setSources(String sources) {
        this.sources = sources;
    }

    public String getArn() {
        return arn;
    }

    public void setArn(String arn) {
        this.arn = arn;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public byte[] getPlaintextKey() { return plaintextKey; }

    public void setPlaintextKey(byte[] plaintextKey) { this.plaintextKey = plaintextKey; }

    public Date getStartDate() { return startDate; }

    public void setStartDate(Date startDate) { this.startDate = startDate; }
}
