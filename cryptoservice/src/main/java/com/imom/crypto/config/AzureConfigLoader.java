package com.imom.crypto.config;

import com.imom.crypto.util.FileLoading;

import java.util.Properties;

public class AzureConfigLoader {

    private AzureConfigLoader() {
    }

    private static final String PROPERTIES_FILE = "/opt/keyvaultfile/config.properties";
    private static Properties properties;

    public static void init() {
        properties = FileLoading.loadFile(PROPERTIES_FILE);
    }

    public static String getTenants() {
        return properties.getProperty("tenants");
    }

    public static String getKVSecrets(String tenant) {
        return properties.getProperty(tenant);
    }

    public static String getCommonKeys() {
        return properties.getProperty("crypto.common.keys");
    }

}
