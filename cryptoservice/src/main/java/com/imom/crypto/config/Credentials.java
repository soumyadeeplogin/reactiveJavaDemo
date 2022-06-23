package com.imom.crypto.config;


import com.imom.crypto.util.FileLoading;

import java.util.Properties;

public class Credentials {

    private Credentials() {
    }

    private static final String PROPERTIES_FILE = "/opt/keyvaultfile/credential.properties";
    private static Properties properties = new Properties();

    public static void init() {
        properties = FileLoading.loadFile(PROPERTIES_FILE);
    }

    public static String getclientID() {
        return properties.getProperty("clientID");
    }

    public static String getclientCred() {
        return properties.getProperty("clientCred");
    }
}
