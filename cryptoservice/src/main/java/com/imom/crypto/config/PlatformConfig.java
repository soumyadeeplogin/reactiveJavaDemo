package com.imom.crypto.config;

import com.imom.crypto.util.FileLoading;

import java.util.Properties;

public class PlatformConfig {

    private PlatformConfig() {
    }

    private static final String PROPERTIES_FILE = "/opt/deployment/buildproperties/crypto/platformconfig.properties";
    private static Properties properties;

    public static void init() {
        properties = FileLoading.loadFile(PROPERTIES_FILE);
    }

    public static String getvalue() {
        return properties.getProperty("platform");
    }
}
