package com.imom.crypto.manager;

import com.imom.crypto.bean.PassData;
import org.apache.log4j.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class KeyManager {

    private KeyManager() {
    }

    private static final Map<String, byte[]> keyMap = new ConcurrentHashMap<>();
    private static final Map<String, PassData> dataMap = new ConcurrentHashMap<>();

    private static final Logger log = Logger.getLogger(KeyManager.class);

    public static void setKey(String tenantId, byte[] key) {
        keyMap.put(tenantId, key);
    }

    public static byte[] getKey(String tenantId) {
        return keyMap.get(tenantId);
    }

    public static void setPassData(String tenantId, PassData data) { dataMap.put(tenantId, data); }

    public static PassData getpassData(String tenantId) { return dataMap.get(tenantId); }

}
