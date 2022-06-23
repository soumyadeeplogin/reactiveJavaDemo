package com.imom.crypto.util;

import com.imom.crypto.api.AWSCredential;
import com.imom.crypto.bean.PassData;
import com.imom.crypto.config.Config;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.manager.KMSKeys;
import com.imom.crypto.service.CMKManagerService;
import com.imom.crypto.service.SecretManagerService;
import com.imom.crypto.subservice.DBService;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.JsonNodeFactory;
import org.codehaus.jackson.node.ObjectNode;
import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;

import static com.imom.crypto.util.Constants.*;

public class KeyGen {
    private static Logger log = Logger.getLogger(KeyGen.class);
    private static final String ERROR = "Error: ";

    public static void init() {
        log = Logger.getLogger(KeyGen.class);
    }

    public static void main(String[] args) {
        try {

            Class.forName("com.mysql.jdbc.Driver").newInstance();

            switch (args[0]) {
                case "dbKey":
                    createDBKey(args[1]);
                    return;
                case "encDBPass":
                    createDBPass(args[1], args[2], args[3].getBytes());
                    break;
                case "genKey":
                    insertKey(args[1], args[2], args[3], args[4]);
                    break;
                case "genSalt":
                    createSalt(args[1], args[2].getBytes(), args[3].getBytes(), args[4], args[5], args[6], args[7], args[8], args[9]);
                    break;
                default:
                    log.info("Illegal arguments");
                    break;
            }

        } catch (Exception ex) {
            log.error(ERROR, ex);
        }
    }

    public static void createDBKey(String path) {
        File file = new File(path);
        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            KeyGenerator keyGen;

            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            byte[] keyBytes = key.getEncoded();
            fileOut.write(keyBytes);

        } catch (IOException | NoSuchAlgorithmException e) {
            log.error(ERROR, e);
        }
    }

    public static void createDBPass(String keyPath, String path, byte[] password) {
        File file = new File(path);
        File keyFile = new File(keyPath);
        FileInputStream input = null;
        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            input = new FileInputStream(keyFile);
            int bytesRead = 0;
            int bytesToRead = (int) keyFile.length();
            byte[] key = new byte[bytesToRead];
            while (bytesRead < bytesToRead) {
                int result = input.read(key, bytesRead, bytesToRead - bytesRead);
                if (result == -1)
                    break;
                bytesRead += result;
            }
            String encPwd = encrypt(password, key);
            if (encPwd != null) {
                fileOut.write(encPwd.getBytes());
            }
        } catch (Exception e) {
            log.error(ERROR, e);
        } finally {
            try {
                if (input != null) {
                    input.close();
                }
            } catch (IOException e) {
                log.error(ERROR, e);
            }
        }

    }

    public static void insertKey(String tenantId, String dbUrl, String userName, String dbPwd) {
        boolean useSecretsManager = Boolean.parseBoolean(Config.getUseSecretsManager());
        PreparedStatement stmt = null;
        DBManager.getAWSCredentials();
        AWSCredential data = DBManager.getCredential(tenantId);
        String secretName = null;
        if (data != null) {
            secretName = data.getSecretName();
        }
        SecretManagerService secretManagerService = new SecretManagerService();
        try {
            if (secretName == null) {
                KeyGenerator keyGen;
                keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey key = keyGen.generateKey();
                byte[] keyBytes = key.getEncoded();
                if (useSecretsManager) {
                    String passKey = new Base64().encodeAsString(keyBytes);
                    ObjectNode secretNode = JsonNodeFactory.instance.objectNode();
                    secretNode.put("refNum", tenantId);
                    secretNode.put("key", passKey);
                    secretManagerService.createSecret(tenantId, secretNode.toString());
                } else {
                    try (Connection conn = DriverManager.getConnection(dbUrl, userName, dbPwd)) {
                        String sql = "insert into ImomKeys ( tenantId, passKey ) values ( ?, ? );";
                        stmt = conn.prepareStatement(sql);
                        stmt.setString(1, tenantId);
                        stmt.setBytes(2, keyBytes);
                        stmt.execute();
                    }
                }
            }
        } catch (Exception ex) {
            log.error(ERROR, ex);
        } finally {
            try {
                if (stmt != null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.error(ERROR, e);
            }
        }
    }

    public static KMSKeys insertCmk(KMSKeys request) {
        CMKManagerService cmkManagerService = new CMKManagerService();
        String password = DBManager.getKeyManagerPassword();
        try {
            //create KMS
            KMSKeys kmsKeys = cmkManagerService.createCmsk(request);
            if (kmsKeys != null) {
                kmsKeys.setUser(request.getUser());
                kmsKeys.setIpAddress(request.getIpAddress());
                //insert KMS details to DB
                insertCmkInDB(kmsKeys,password);
                //insert KMS audit logs to DB
                auditlog(kmsKeys,CREATED,password);
                //Send kafka event
                KafkaAlertSending.sendAlerttoKakfa(kmsKeys.getTenantId(),AlertNames.Key_Created_Alert.getValue(), Config.getCreateEmailSubject()+" for "+kmsKeys.getTenantId(),Config.getCreateEmailMsg());
            }
            return kmsKeys;
        } catch (Exception ex) {
            log.error(ERROR, ex);
            return null;
        }
    }


    public static KMSKeys rotateCmk(KMSKeys request) {
        CMKManagerService cmkManagerService = new CMKManagerService();
        String dbPwd = DBManager.getKeyManagerPassword();
        KMSKeys kmsKeys = null;
        try {
            //rotate key
            kmsKeys = cmkManagerService.rotateCmsk(request, dbPwd);
            if(kmsKeys != null) {
                kmsKeys.setUser(request.getUser());
                kmsKeys.setIpAddress(request.getIpAddress());
                //insert KMS details to DB
                insertCmkInDB(kmsKeys,dbPwd);
                //insert KMS audit logs to DB
                auditlog(kmsKeys,CREATED,dbPwd);
                //Send kafka event
                KafkaAlertSending.sendAlerttoKakfa(kmsKeys.getTenantId(),AlertNames.Key_Rotated_Alert.getValue(), Config.getRotateEmailSubject()+" for "+kmsKeys.getTenantId(),Config.getRotateEmailMsg());
            }
        } catch (Exception ex) {
            log.error(ERROR, ex);
        }
        return kmsKeys;
    }

    public static void migrateTenants(String ipAdress) {
        CMKManagerService cmkManagerService = new CMKManagerService();
        String keyPassword = DBManager.getKeyManagerPassword();
        //Get pass and salt from DB with tenantId
        Map<String, PassData> passDataMap = DBManager.getPassData();
        //Get tenants list
        for (String tenantId:passDataMap.keySet()) {
            //check if tenant is present in KMS or not
            if(DBManager.getCmks(tenantId) == null && passDataMap.get(tenantId) != null) {
                try {
                    DBService dbService = new DBService();
                    //generate plaintext key from pass and salt
                    byte[] plainText = dbService.generateKey(passDataMap.get(tenantId));
                    if( plainText != null) {
                        try {
                            //create KMS with AWS_KMS as source and plaintext key from pass and salt
                            KMSKeys kmsKeys = cmkManagerService.migrateKMS(tenantId,"AWS_KMS",plainText);
                            if (kmsKeys != null) {
                                kmsKeys.setIpAddress(ipAdress);
                                kmsKeys.setUser("System");
                                insertCmkInDB(kmsKeys,keyPassword);
                                auditlog(kmsKeys,CREATED,keyPassword);
                            }
                        } catch (Exception ex) {
                            log.error("ERROR "+ex.getMessage(),ex);
                        }
                    }
                } catch (Exception ex) {
                    log.error("ERROR "+ex.getMessage(),ex);
                }
            }
        }
    }

    private static void auditAlerts(JSONObject jsobj,String actionType,String dbPwd) {
        KMSKeys kmsKeys = new KMSKeys();
        kmsKeys.setKeyId("Not Available");
        kmsKeys.setUser(jsobj.getString("user"));
        kmsKeys.setTenantId(jsobj.getString("tenantId"));
        kmsKeys.setIpAddress(jsobj.getString("ipAddress"));
        auditlog(kmsKeys,actionType,dbPwd);
    }

    public static void addAlertConfig(JSONObject jsobj, String dbPwd) {
        List<String> alertsType = Arrays.asList("Create Alert","Rotate Alert");
        try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
            String sql = "insert into alertsConfig (tenantId,alertType , frequency , days, toemails , notification,cc, user) values ( ?, ? , ? , ? , ?, ?, ? ,? );";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, jsobj.getString("tenantId"));
            stmt.setString(2, jsobj.getString("alertType"));
            if (alertsType.contains(jsobj.getString("alertType"))) stmt.setInt(3, 0);
            else stmt.setInt(3, Integer.valueOf(jsobj.getString("frequency")));
            if (alertsType.contains(jsobj.getString("alertType"))) stmt.setInt(4, 0);
            else stmt.setInt(4, Integer.valueOf(jsobj.getString("days")));
            stmt.setString(5,jsobj.getString("to"));
            stmt.setString(6,jsobj.getString("notification"));
            stmt.setString(7, jsobj.getString("cc"));
            stmt.setString(8,jsobj.getString("user"));
            stmt.execute();
            auditAlerts(jsobj,ALERTCREATED,dbPwd);
        } catch (Exception e) {
            log.error("Error "+e,e);
        }
    }

    public static void auditAlertHistory(JSONObject jsobj,String status) {
        Date now = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        try (Connection conn = DriverManager.getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(),
                DBManager.getKeyPassword())) {
            String sql = "insert into alertHistory (uuid,triggertime , subject , status,tenantId,event,alertType) values ( ?, ? , ? ,? ,? ,?,?);";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, jsobj.getString("uuid"));
            stmt.setTimestamp(2, Timestamp.valueOf(formatter.format(now)));
            stmt.setString(3, jsobj.getJSONArray("alertCommunication").getJSONObject(0).getString("subject"));
            stmt.setString(4,status);
            stmt.setString(5,jsobj.getString("refnum"));
            stmt.setString(6, jsobj.toString());
            stmt.setString(7, jsobj.getString("alertType"));
            stmt.execute();
        } catch (Exception e) {
            log.error("Error "+e,e);
        }
    }

    public static void deleteAlertConfig(JSONObject jsobj, String dbPwd) {
        try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
            String sql = "delete from alertsConfig where tenantId = ? and alertType = ? ;";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1,jsobj.getString("tenantId"));
            stmt.setString(2,jsobj.getString("alertType"));
            stmt.execute();
            auditAlerts(jsobj,ALERTDELETED,dbPwd);
        } catch (Exception e) {
            log.error("Error "+e,e);
        }
    }


    public static void updateAlertConfig(JSONObject jsobj, String dbPwd) {
        try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
            String sql = "update alertsConfig set frequency = ? , days = ? , toemails = ? , notification = ? , cc = ? , user = ? where tenantId = ? and alertType = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setInt(1, Integer.valueOf(jsobj.getString("frequency")));
            stmt.setInt(2,  Integer.valueOf(jsobj.getString("days")));
            stmt.setString(3,jsobj.getString("to"));
            stmt.setString(4,jsobj.getString("notification"));
            stmt.setString(5, jsobj.getString("cc"));
            stmt.setString(6,jsobj.getString("user"));
            stmt.setString(7, jsobj.getString("tenantId"));
            stmt.setString(8, jsobj.getString("alertType"));
            stmt.execute();
            auditAlerts(jsobj,ALERTMODIFIED,dbPwd);
        } catch (Exception e) {
            log.error("Error "+e,e);
        }
    }

    public static List<Map<String,Object>> getAlertConfig(String tenantId,String dbUrl, String userName, String dbPwd) {
        try {
            List<Map<String,Object>> alerts = new ArrayList<>();
            String query = "select * from alertsConfig where tenantId = ?;";
            try (Connection conn = DriverManager.getConnection(dbUrl, userName, dbPwd)) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, tenantId);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            Map<String,Object> alert = new HashMap<>();
                            try {
                                alert.put("alertType",rs.getString("alertType"));
                                alert.put("frequency",rs.getInt("frequency"));
                                alert.put("days",rs.getInt("days"));
                                alert.put("to",rs.getString("toemails"));
                                alert.put("cc",rs.getString("cc"));
                                alert.put("notification",rs.getString("notification"));
                                alerts.add(alert);
                            } catch (Exception e) {
                                log.error("Error while getting alert config from db" + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
            return alerts;
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }

    public static List<Map<String,Object>> getAlertHistory(String tenantId,String dbUrl, String userName, String dbPwd) {
        try {
            List<Map<String,Object>> alerts = new ArrayList<>();
            String query = "select * from alertHistory where tenantId = ?;";
            try (Connection conn = DriverManager.getConnection(dbUrl, userName, dbPwd)) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, tenantId);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            Map<String,Object> alert = new HashMap<>();
                            try {
                                alert.put("uuid",rs.getString("uuid"));
                                alert.put("alertType",rs.getString("alertType"));
                                alert.put("subject",rs.getString("subject"));
                                alert.put("tenantId",rs.getString("tenantId"));
                                alert.put("event",rs.getString("event"));
                                alert.put("triggertime",rs.getTimestamp("triggertime"));
                                alerts.add(alert);
                            } catch (Exception e) {
                                log.error("Error while getting alert History from db" + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
            return alerts;
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }

    public static List<Map<String,Object>> getActivityLogs(String tenantId, String dbPwd,boolean logs) {
        try {
            List<Map<String,Object>> activities = new ArrayList<>();
            String query = "select * from CryptoAuditLog where tenantId = ?;";
            if(logs) query = "select * from CryptoAuditLog where tenantId = ? order by actionDate DESC;";
            try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, tenantId);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            Map<String,Object> activity = new HashMap<>();
                            try {
                                activity.put("entityType",rs.getString("entityType"));
                                activity.put("userId",rs.getString("userId"));
                                activity.put("tenantId",rs.getString("tenantId"));
                                activity.put("actionDate",rs.getTimestamp("actionDate"));
                                activity.put("actionType",rs.getString("actionType"));
                                activity.put("ipAddress",rs.getString("ipAddress"));
                                activities.add(activity);
                            } catch (Exception e) {
                                log.error("Error while getting activities logs from db" + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
            return activities;
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }

    public static Map<String,Integer> getKeyAgeConfig(String tenantId) {
        Map<String, Integer> details = new HashMap<>();
        try {
            String query = "select * from keyAgeConfig where tenantId = ?;";
            try (Connection conn = DriverManager.getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(),
                    DBManager.getKeyPassword())) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, tenantId);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            try {
                                details.put(tenantId,rs.getInt("keyAge"));
                            } catch (Exception e) {
                                log.error("Error while getting alert config from db" + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
            return details;
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }

    public static Map<String,String> getRecipientList(String tenantId,String alertType) {
        Map<String ,String > details = new HashMap<>();
        try {
            String query = "select * from alertsConfig where tenantId = ? and alertType = ? ;";
            try (Connection conn = DriverManager.getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(),
                    DBManager.getKeyPassword())) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, tenantId);
                    stmt.setString(2, alertType);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            try {
                                details.put("days",String.valueOf(rs.getInt("days")));
                                details.put("to",rs.getString("toemails"));
                                details.put("cc",rs.getString("cc"));
                            } catch (Exception e) {
                                log.error("Error while getting alert config from db" + e.getMessage(), e);
                            }
                        }
                    }
                }
            }
            return details;
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }

    public static void auditlog(KMSKeys kmsKeys,String actionType,String dbPwd) {
        Date now = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
            String sql = "insert into CryptoAuditLog (entityType, userId , tenantId , actionDate, ipAddress , actionType) values ( ?, ? , ? , ? , ?, ? );";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, kmsKeys.getKeyId());
            stmt.setString(2, kmsKeys.getUser());
            stmt.setString(3, kmsKeys.getTenantId());
            stmt.setTimestamp(4, Timestamp.valueOf(formatter.format(now)));
            stmt.setString(5, kmsKeys.getIpAddress());
            stmt.setString(6,actionType);
            stmt.execute();
        } catch (Exception e) {
            log.error("Error "+e,e);
        }
    }

    private static void insertCmkInDB(KMSKeys kmsKeys,String dbPwd) {
        Date now = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
            String sql = "insert into CMKeys (arn ,keyId, tenantId,createdTimestamp, active,source) values ( ?, ? , ? , ? , ?, ? );";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, kmsKeys.getArn());
            stmt.setString(2, kmsKeys.getKeyId());
            stmt.setString(3, kmsKeys.getTenantId());
            stmt.setTimestamp(4, Timestamp.valueOf(formatter.format(now)));
            stmt.setBoolean(5, true);
            stmt.setString(6, kmsKeys.getSources());
            stmt.execute();
        } catch (Exception e) {
            log.error("Error "+e,e);
        }
    }

    public static void updateCmkStatus(KMSKeys kmsKeys, String dbPwd) {
        try {
            try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
                String sql = "update CMKeys set active = ? where keyId = ?;";
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setBoolean(1, false);
                    stmt.setString(2, kmsKeys.getKeyId());
                    stmt.execute();
                }
            }
            log.info("active status is updated successfully in DB");
        } catch (Exception ex) {
            log.error("ERROR :: error while update active status of keyId ", ex);
        }
    }

    public static void deleteCMk(KMSKeys kmsKeys, String dbPwd) {
        kmsKeys.setUser("System");
        kmsKeys.setIpAddress("System");
        String query = "select keyId from CMKeys where tenantId = ? and active = ? order by ts DESC limit 3,1000;";
        CMKManagerService cmkManagerService = new CMKManagerService();
        SecretManagerService secretManagerService = new SecretManagerService();
        try {
            try (Connection conn = DriverManager.getConnection(Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), dbPwd)) {
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, kmsKeys.getTenantId());
                    stmt.setBoolean(2, false);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            kmsKeys.setKeyId(rs.getString("keyId"));
                            cmkManagerService.scheduleKeyTODelete(kmsKeys.getKeyId());
                            secretManagerService.deleteSecrete(kmsKeys.getTenantId(),kmsKeys.getKeyId());
                            auditlog(kmsKeys,DELETED,dbPwd);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
    }

    public static void createSalt(String tenantId, byte[] pwd, byte[] salt, String dbUrl, String userName, String dbPwd,
                                  String keyDbUrl, String keyDBUser, String keyDBPass) {
        byte[] key = null;
        Boolean useSecretsManager = Boolean.valueOf(Config.getUseSecretsManager());
        SecretManagerService secretManagerService = new SecretManagerService();

        if (useSecretsManager) {
            ObjectNode secretNode;
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                String secret = secretManagerService.getSecret(tenantId);
                if (secret != null) {
                    secretNode = (ObjectNode) objectMapper.readTree(secret);
                    if (secretNode.size() > 0 && secretNode.has("key") && secretNode.get("key") != null) {
                        String passkey = secretNode.get("key").asText();
                        key = Base64.decodeBase64(passkey);
                    } else {
                        log.error("key is not present or null for " + tenantId);
                    }
                } else {
                    log.error("Error ::: " + tenantId + " is null in SecretsManager");
                }
            } catch (Exception e) {
                log.error(ERROR + e.getMessage(), e);
            }
        } else {
            ResultSet keyRs = null;
            try {
                try (Connection keyConn = DriverManager.getConnection(keyDbUrl, keyDBUser, keyDBPass)) {
                    try (Statement keyStmt = keyConn.createStatement()) {
                        keyRs = keyStmt.executeQuery("select passKey from ImomKeys where tenantId='" + tenantId + "'");
                        while (keyRs.next()) {
                            key = keyRs.getBytes("passKey");
                        }
                    }
                }
            } catch (Exception ex) {
                log.error(ERROR + ex.getMessage(), ex);
            } finally {
                try {
                    if (keyRs != null) {
                        keyRs.close();
                    }
                } catch (SQLException e) {
                    log.error(ERROR + e.getMessage(), e);
                }
            }
        }

        if (key != null) {
            String passString = encrypt(pwd, key);
            String saltString = encrypt(salt, key);
            byte[] encryptedPass;
            byte[] encryptedSalt;
            if (passString != null && saltString != null) {
                encryptedPass = passString.getBytes();
                encryptedSalt = saltString.getBytes();
                try (Connection conn = DriverManager.getConnection(dbUrl, userName, dbPwd)) {
                    String sql = "insert into ImomKeys (tenantId, passwd, salt) values(?,?,?);";
                    try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                        stmt.setString(1, tenantId);
                        stmt.setBytes(2, encryptedPass);
                        stmt.setBytes(3, encryptedSalt);
                        stmt.execute();
                    }
                } catch (SQLException e) {
                    log.error(ERROR + e.getMessage(), e);
                }
            } else {
                log.error(ERROR + " null values after encryption of pass and salt");
            }
        } else {
            log.error("Error: passKey is null, can't create salt");
        }

    }

    public static String encrypt(byte[] arrayToEncrypt, byte[] key) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            log.error(ERROR + e.getMessage(), e);
        }
        final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        try {
            if (cipher != null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
        } catch (InvalidKeyException e) {
            log.error(ERROR + e.getMessage(), e);
        }
        String encryptedString = null;
        try {
            if (cipher != null) {
                encryptedString = Base64.encodeBase64String(cipher.doFinal(arrayToEncrypt));
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            log.error(ERROR + e.getMessage(), e);
        }
        return encryptedString;
    }

    public static void insertKeyManager(String tenantId, String keyManagerUrl, String keyManagerUserNamel,
                                        String keyManagerPassword, byte[] secretKey, byte[] accessKey, byte[] secretName, byte[] awsRegion) {
        byte[] key = null;
        File keyFile = new File(Config.getKeyFile());
        try (FileInputStream keyInput = new FileInputStream(Config.getKeyFile())) {
            int fileBytesRead = 0;
            int fileBytesToRead = (int) keyFile.length();
            key = new byte[fileBytesToRead];
            while (fileBytesRead < fileBytesToRead) {
                int result = keyInput.read(key, fileBytesRead, fileBytesToRead - fileBytesRead);
                if (result == -1)
                    break;
                fileBytesRead += result;
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
        String accessKeyString = encrypt(accessKey, key);
        String secretKeyString = encrypt(secretKey, key);
        byte[] encryptedSecretName = null;
        if (secretName != null || !"".equals(secretName)) {
            if (secretName != null && !"".equals(new String(secretName).trim())) {
                String secretNameString = encrypt(secretName, key);
                encryptedSecretName = secretNameString.getBytes();
            }
            byte[] encryptedRegion = null;
            if (awsRegion != null || !"".equals(awsRegion))
                if (awsRegion != null && !"".equals(new String(awsRegion).trim())) {
                    String regionString = encrypt(awsRegion, key);
                    encryptedRegion = regionString.getBytes();
                }
            byte[] encryptedAccessKey;
            byte[] encryptedSecretKey;
            if (accessKeyString != null && secretKeyString != null) {
                encryptedAccessKey = accessKeyString.getBytes();
                encryptedSecretKey = secretKeyString.getBytes();
                try (Connection conn = DriverManager.getConnection(keyManagerUrl, keyManagerUserNamel,
                        keyManagerPassword)) {
                    String sql = "insert into credentials (tenantId, accesskey, secretkey,secretname,region) values(?,?,?,?,?);";
                    try (PreparedStatement statement = conn.prepareStatement(sql)) {
                        statement.setString(1, tenantId);
                        statement.setBytes(2, encryptedAccessKey);
                        statement.setBytes(3, encryptedSecretKey);
                        statement.setBytes(4, encryptedSecretName);
                        statement.setBytes(5, encryptedRegion);
                        statement.execute();
                    }
                } catch (SQLException e) {
                    log.error(ERROR + e.getMessage(), e);
                }
            } else {
                log.error(ERROR + " null values after encryption of accessKey and secretKey");
            }
        }
    }
}
