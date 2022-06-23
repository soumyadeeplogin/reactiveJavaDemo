package com.imom.crypto.subservice;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.windowsazure.core.pipeline.filter.ServiceRequestContext;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.log4j.Logger;

import java.net.MalformedURLException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


public class CustomKeyVaultCredentials extends KeyVaultCredentials {
    private static final Logger log = Logger.getLogger(CustomKeyVaultCredentials.class);
    private String applicationId;
    private String applicationSecret;
    private static final String ERROR = "Error : ";

    public CustomKeyVaultCredentials(String applicationId, String applicationSecret) {
        this.setApplicationId(applicationId);
        this.setApplicationSecret(applicationSecret);
    }

    public String getApplicationId() {
        return applicationId;
    }

    private void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    private void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    @Override
    public Header doAuthenticate(ServiceRequestContext request, Map<String, String> challenge) {
        AuthenticationResult res = null;
        String authorization = challenge.get("authorization");
        String resource = challenge.get("resource");
        try {
            res = getAccessToken(authorization, resource);
            if (res != null) {
                return new BasicHeader("Authorization", res.getAccessTokenType() + " " + res.getAccessToken());
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
        return null;
    }

    private AuthenticationResult getAccessToken(String authorization, String resource)
            throws InterruptedException, ExecutionException {
        AuthenticationContext ctx = null;
        ExecutorService service = Executors.newFixedThreadPool(1);
        try {
            ctx = new AuthenticationContext(authorization, false, service);
            Future<AuthenticationResult> resp = ctx.acquireToken(resource, new ClientCredential(
                    this.getApplicationId(), this.getApplicationSecret()), null);
            if (resp != null) {
                return resp.get();
            }
        } catch (MalformedURLException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
