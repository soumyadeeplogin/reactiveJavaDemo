package com.imom.crypto.db;

import com.imom.crypto.api.AWSCredential;
import com.imom.crypto.bean.PassData;
import com.imom.crypto.config.Config;
import com.imom.crypto.manager.KMSKeys;
import com.imom.crypto.manager.KeyManager;
import com.imom.crypto.service.CMKManagerService;
import com.imom.crypto.service.SecretManagerService;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ObjectNode;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.FileInputStream;
import java.sql.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static com.imom.crypto.util.Constants.*;

public class DBManager {

    private DBManager() { }

    private static Logger log = Logger.getLogger(DBManager.class);
    private static final HashSet<String> tenants = new HashSet<>();
    private static final Map<String, AWSCredential> crefentials = new ConcurrentHashMap<>();
    private static final Map<String, KMSKeys> cmks = new ConcurrentHashMap<>();
    private static final Map<String,String> keysTenants = new ConcurrentHashMap<>();

    public static void setKeysTenants(String keyId , String tenantId) { keysTenants.put(keyId,tenantId); }

    public static String getTenant (String keyId) { return keysTenants.get(keyId); }

    public static void setCmks(String tenantId, KMSKeys key) {
        cmks.put(tenantId, key);
    }

    public static Map<String, KMSKeys> getCmks() {return cmks ;}

    public static KMSKeys getCmks(String tenantId) { return cmks.get(tenantId); }

    public static Set<String> getTenants() { return tenants; }

    public static void setTenants(String tenantId) {tenants.add(tenantId);}

    public static void setCredential(String tenantId, AWSCredential value) {
        crefentials.put(tenantId, value);
    }

    public static AWSCredential getCredential(String tenantId) {
        return crefentials.get(tenantId);
    }

    public static void init() {
        log = Logger.getLogger(DBManager.class);
        reloadMaps();
    }

    /***
     * reloads the keys into the map
     *
     * @return success/failure response
     */
    public static Response reloadMaps() {
        Response response = null;
        try {
            Class.forName("com.mysql.jdbc.Driver").newInstance();
            createTenantsList();
            getAWSCredentials();
            getCmkeys();
            getKeys();
            response = Response.status(Response.Status.OK).entity("tenants list updated").build();
            log.info("tenants list updated");
        } catch (Exception e) {
            response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
            log.error(ERROR + e.getMessage(), e);
        }
        return response;
    }

    public static void getKeys() {
        Boolean useSecretsManager = Boolean.valueOf(Config.getUseSecretsManager());
        if (useSecretsManager) {
            SecretManagerService secretManagerService = new SecretManagerService();
            CMKManagerService cmkManagerService = new CMKManagerService();
            ObjectNode secretNode;
            ObjectMapper objectMapper = new ObjectMapper();
            for (String tenantId : getTenants()) {
                try {
                    String secret = secretManagerService.getSecret(tenantId+CMK);
                    if (secret != null ) {
                        secretNode = (ObjectNode) objectMapper.readTree(secret);
                        if (secretNode.size() > 0 && secretNode.has(KEY) && secretNode.get(KEY) != null) {
                            String key = secretNode.get(KEY).asText();
                            byte[] byteText = Base64.decodeBase64(key);
                            KeyManager.setKey(tenantId, cmkManagerService.getPlaintextKey(byteText));
                        } else {
                            log.error("key is not present or null for " + tenantId);
                        }
                    } else {
                        log.error("Error ::: " + tenantId + " is null in SecretsManager");
                    }
                } catch (Exception e) {
                    log.error(ERROR + e.getMessage(), e);
                }
            }
        } else {
            try {
                String password = getKeyPassword();
                try (Connection conn = DriverManager.getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(),
                        password)) {
                    try (Statement stmt = conn.createStatement()) {
                        try (ResultSet rs = stmt.executeQuery("select * from ImomKeys;")) {
                            while (rs.next()) {
                                String tenantId = rs.getString(TENANT_ID);
                                log.info("==tenantId===" + tenantId);
                                KeyManager.setKey(tenantId, rs.getBytes("passKey"));
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.error(ERROR + e.getMessage(), e);
            }
        }
    }

    public static void getCmkeys() {
        Set<KMSKeys> activeCmks = getActiveCmks();
        for (KMSKeys kmsKeys : activeCmks) {
            setCmks(kmsKeys.getTenantId(), kmsKeys);
            setKeysTenants(kmsKeys.getKeyId(),kmsKeys.getTenantId());
        }
    }

    public static Set<KMSKeys> getActiveCmks() {
        try {
            Set<KMSKeys> activeKMS = new HashSet<>();
            String password = getKeyPassword();
            String query = "select * from CMKeys where active = ?;";
            try (Connection conn = DriverManager.getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(),password)) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setBoolean(1, true);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            KMSKeys kmsKeys = new KMSKeys();
                            try {
                                kmsKeys.setKeyId(rs.getString("keyId"));
                                kmsKeys.setSources(rs.getString("source"));
                                kmsKeys.setArn(rs.getString("arn"));
                                kmsKeys.setTenantId(rs.getString("tenantId"));
                                kmsKeys.setStartDate(rs.getTimestamp("createdTimestamp"));
                                activeKMS.add(kmsKeys);
                            } catch (Exception e) {
                                log.error("Error while getting cmkeys from db" + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
            return activeKMS;
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }


    public static List<KMSKeys> getKeyInfo(String tenantId) {
        List<KMSKeys> arnList = new ArrayList<>();
        if(tenants.contains(tenantId)) {
            try {
                String password = getKeyPassword();
                String query = "select * from CryptoAuditLog where tenantId = ?;";
                try (Connection conn = DriverManager.getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(),
                        password)) {
                    try (PreparedStatement stmt = conn.prepareStatement(query)) {
                        stmt.setString(1, tenantId);
                        try (ResultSet rs = stmt.executeQuery()) {
                            while (rs.next()) {
                                KMSKeys kmsKeys = new KMSKeys();
                                try {
                                    kmsKeys.setKeyId(rs.getString("entityType"));
                                    kmsKeys.setTenantId(rs.getString("tenantId"));
                                    kmsKeys.setUser(rs.getString("userId"));
                                    kmsKeys.setStartDate(rs.getTimestamp("actionDate"));
                                    kmsKeys.setStatus(rs.getString("actionType"));
                                    kmsKeys.setIpAddress(rs.getString("ipAddress"));
                                    arnList.add(kmsKeys);
                                } catch (Exception e) {
                                    log.error("Error while getting cmkeys from db" + e.getMessage(), e);
                                }
                            }
                        }
                    }
                }
            } catch (Exception ex) {

            }
        }
        return arnList;
    }

    public static void getAWSCredentials() {
        File keyFile = new File(Config.getKeyFile());
        try (FileInputStream keyInput = new FileInputStream(Config.getKeyFile())) {
            int fileBytesRead = 0;
            int fileBytesToRead = (int) keyFile.length();
            byte[] key = new byte[fileBytesToRead];
            while (fileBytesRead < fileBytesToRead) {
                int result = keyInput.read(key, fileBytesRead, fileBytesToRead - fileBytesRead);
                if (result == -1)
                    break;
                fileBytesRead += result;
            }
            String password = getKeyManagerPassword();
            try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(),
                    Config.getKeyManagerUserNamel(), password)) {
                try (Statement stmt = conn.createStatement()) {
                    try (ResultSet rs = stmt.executeQuery("select * from credentials;")) {
                        while (rs.next()) {
                            String tenantId = null;
                            AWSCredential data = new AWSCredential();
                            try {
                                tenantId = rs.getString(TENANT_ID);
                                byte[] encAccessKey = rs.getBytes(ACCESS_KEY);
                                byte[] encSecretKey = rs.getBytes(SECRET_KEY);
                                byte[] encSecretName = rs.getBytes(SECRET_NAME);
                                byte[] encRegion = rs.getBytes(REGION);
                                data.setAccessKey(new String(decrypt(new String(encAccessKey), key)));
                                data.setSecretKey(new String(decrypt(new String(encSecretKey), key)));
                                if (encSecretName != null)
                                    data.setSecretName(new String(decrypt(new String(encSecretName), key)));
                                if (encRegion != null)
                                    data.setAwsRegion(new String(decrypt(new String(encRegion), key)));
                                crefentials.put(tenantId, data);
                            } catch (Exception e) {
                                log.error("Error while getting  for AWSCredentials " + tenantId + "  " + e.getMessage(),
                                        e);
                            }
                        }
                    }
                }
            }
        } catch (Exception e1) {
            log.error(ERROR + e1.getMessage(), e1);
        }
    }

    public static byte[] decrypt(String stringToDecrypt, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(Config.getPadding());
        final SecretKeySpec secretKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        final String decryptedString = new String(cipher.doFinal(Base64.decodeBase64(stringToDecrypt)));
        return decryptedString.getBytes();
    }

    public static String getKeyPassword() {
        return getPasswords(Config.getKeyPassFile(), Config.getKeyFile());
    }

    public static String getPassword() {
        return getPasswords(Config.getPassFile(), Config.getKeyFile());
    }

    public static String getKeyManagerPassword() {
        return getPasswords(Config.getKeyManagerPassFile(), Config.getKeyFile());
    }

    private static String getPasswords(String passFilePath, String keyFilePath) {
        File passFile = new File(passFilePath);
        File keyFile = new File(keyFilePath);
        try {
            try (FileInputStream input = new FileInputStream(passFile)) {
                int bytesRead = 0;
                int bytesToRead = (int) passFile.length();
                byte[] pass = new byte[bytesToRead];
                while (bytesRead < bytesToRead) {
                    int result = input.read(pass, bytesRead, bytesToRead - bytesRead);
                    if (result == -1)
                        break;
                    bytesRead += result;
                }
                try (FileInputStream keyInput = new FileInputStream(keyFile)) {
                    int fileBytesRead = 0;
                    int fileBytesToRead = (int) keyFile.length();
                    byte[] key = new byte[fileBytesToRead];
                    while (fileBytesRead < fileBytesToRead) {
                        int result = keyInput.read(key, fileBytesRead, fileBytesToRead - fileBytesRead);
                        if (result == -1)
                            break;
                        fileBytesRead += result;
                    }
                    return new String(decrypt(new String(pass), key));
                }
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
        return null;
    }


    public static void createTenantsList() {
            try {
                Class.forName("com.mysql.jdbc.Driver").newInstance();
                try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(),getKeyManagerPassword())) {
                    try (Statement stmt = conn.createStatement()) {
                        try (ResultSet rs = stmt.executeQuery(QUERY_SELECT_ALL_CMKEYS)) {
                            while (rs.next())
                                setTenants(rs.getString(TENANT_ID));
                        }
                    }
                }
            } catch (Exception e) {
                log.error(ERROR + e.getMessage(), e);
            }
            log.info("cmks tenants list : " + tenants.toString());
    }


    public static Set<String> getTenandId() {
        Set<String> tenants = new HashSet<>();
        try {
            Class.forName("com.mysql.jdbc.Driver").newInstance();
            try (Connection conn = DriverManager.getConnection(Config.getPassUrl(), Config.getPassUserNamel(),getPassword())) {
                try (Statement stmt = conn.createStatement()) {
                    try (ResultSet rs = stmt.executeQuery("select * from ImomKeys;")) {
                        while (rs.next())
                            tenants.add(rs.getString(TENANT_ID));
                    }
                }
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
        return tenants;
    }

    public static  Map<String,PassData> getPassData() {
        Map<String,PassData> passDataMap = new HashMap<>();
        try {
            try (Connection conn = DriverManager.getConnection(Config.getPassUrl(), Config.getPassUserNamel(), getPassword())) {
                try (Statement stmt = conn.createStatement()) {
                    try (ResultSet rs = stmt.executeQuery("select * from ImomKeys;")) {
                        while (rs.next()) {
                            String tenantId = null;
                            try {
                                tenantId = rs.getString(TENANT_ID);
                                PassData data = new PassData();
                                byte[] passwd = rs.getBytes("passwd");
                                byte[] salt = rs.getBytes("salt");
                                //get key pass secrete manager
                                byte[] secrete = getSecreteKey(tenantId);
                                if(secrete != null) {
                                    data.setPasswd(decrypt(new String(passwd),secrete ));
                                    data.setSalt(decrypt(new String(salt),secrete ));
                                    passDataMap.put(tenantId,data);
                                }
                            } catch (Exception e) {
                                log.error("Error while getting passdata for " + tenantId + "  " + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
        return passDataMap;
    }

    private static byte[] getSecreteKey(String tenantId) {
        SecretManagerService secretManagerService = new SecretManagerService();
        ObjectNode secretNode;
        ObjectMapper objectMapper = new ObjectMapper();
            try {
                String secret = secretManagerService.getSecret(tenantId);
                if (secret != null ) {
                    secretNode = (ObjectNode) objectMapper.readTree(secret);
                    if (secretNode.size() > 0 && secretNode.has(KEY) && secretNode.get(KEY) != null) {
                        String key = secretNode.get(KEY).asText();
                         return Base64.decodeBase64(key);
                    } else {
                        log.error("key is not present or null for " + tenantId);
                        return null;
                    }
                } else {
                    log.error("Error ::: " + tenantId + " is null in SecretsManager");
                    return null;
                }
            } catch (Exception e) {
                log.error(ERROR + e.getMessage(), e);
                return null;
            }
    }

}
