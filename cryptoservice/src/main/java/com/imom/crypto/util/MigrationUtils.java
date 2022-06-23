package com.imom.crypto.util;

import com.imom.crypto.config.Config;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.service.SecretManagerService;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.codehaus.jackson.node.JsonNodeFactory;
import org.codehaus.jackson.node.ObjectNode;

import java.sql.*;

public class MigrationUtils {

    private static final Logger log = Logger.getLogger(MigrationUtils.class);
    private static final String ERROR = "Error: ";
    SecretManagerService secretManagerService = new SecretManagerService();

    /***
     * migrate keys from mysql to aws secrets-manager.
     */
    public void migrate() {

        fetchKeyAndCreateSecret();
        listSecrets();
    }

    public Connection getConnection(String url, String userName, String password) {
        try {
            return DriverManager.getConnection(url, userName, password);
        } catch (SQLException e) {
            log.error(ERROR + e.getMessage(), e);
        }
        return null;
    }

    private void fetchKeyAndCreateSecret() {

        try {
            Boolean useSecretsManager = Boolean.valueOf(Config.getUseSecretsManager());
            if (useSecretsManager) {
                String password = DBManager.getKeyPassword();
                try (Connection conn = getConnection(Config.getKeyUrl(), Config.getKeyUserNamel(), password)) {
                    try (Statement stmt = conn.createStatement()) {
                        try (ResultSet rs = stmt.executeQuery("select * from ImomKeys")) {
                            while (rs.next()) {
                                try {
                                    String tenantId = rs.getString("tenantId");
                                    log.info("===tenantId===" + tenantId);
                                    String key = new Base64().encodeAsString(rs.getBytes("passKey"));

                                    ObjectNode secretNode = JsonNodeFactory.instance.objectNode();
                                    secretNode.put("refNum", tenantId);
                                    secretNode.put("key", key);

                                    secretManagerService.createSecret(tenantId, secretNode.toString());
                                } catch (Exception e) {
                                    log.error(ERROR + e.getMessage(), e);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
    }


    private void listSecrets() {
        secretManagerService.listSecrets();
    }

}
