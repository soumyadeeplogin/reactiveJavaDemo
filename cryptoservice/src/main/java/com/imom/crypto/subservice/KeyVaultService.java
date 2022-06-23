package com.imom.crypto.subservice;


import com.imom.crypto.bean.PassData;
import com.imom.crypto.config.AzureConfigLoader;
import com.imom.crypto.config.Credentials;
import com.imom.crypto.manager.KeyManager;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.KeyVaultClientService;
import com.microsoft.azure.keyvault.KeyVaultConfiguration;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.Secret;
import com.microsoft.windowsazure.Configuration;
import org.apache.log4j.Logger;

import java.util.concurrent.Future;

public class KeyVaultService implements SubService {

    private static final Logger log = Logger.getLogger(KeyVaultService.class);

    static String clientID = Credentials.getclientID();
    static String clientCred = Credentials.getclientCred();


    static KeyVaultCredentials kvCred = new CustomKeyVaultCredentials(clientID, clientCred);
    static Configuration config = KeyVaultConfiguration.configure(null, kvCred);
    static KeyVaultClient kvc = KeyVaultClientService.create(config);

    static DBService dbs = new DBService();

    static {
        getSecrets();
    }

    private static void getSecrets() {
        try {

            String tenants = AzureConfigLoader.getTenants();
            String[] tenant_arr = tenants.split(",");
            for (String tenant : tenant_arr) {

                String secrets = AzureConfigLoader.getKVSecrets(tenant);
                String[] secrets_arr = secrets.split(",");

                if (secrets_arr.length != 2) break;

                String pwd_url = secrets_arr[0];
                String salt_url = secrets_arr[1];

                Future<Secret> kvpwd = kvc.getSecretAsync(pwd_url);
                Future<Secret> kvsalt = kvc.getSecretAsync(salt_url);

                PassData data = new PassData();
                data.setPasswd(kvpwd.get().getValue().getBytes()); // password
                data.setSalt(kvsalt.get().getValue().getBytes()); // salt

                KeyManager.setPassData(tenant, data);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override
    public String cipherMethod(String mode, String tenantid, String value) {
        try {
            if (mode.equals("encrypt") || mode.equals("decrypt")) {
                return dbs.cipherMethod(mode, tenantid, value);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

}
