package com.imom.crypto.util;

public enum AlertNames {

    Key_Rotated_Alert("Key Rotated Alert"),
    Key_Created_Alert("Key Created Alert"),
    AWS_Access_Alerts("AWS Access Alerts"),
    AWS_Expiry_Alerts("Key Expiry Alert");
    private String value;

    private AlertNames (String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}
