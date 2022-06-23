package com.imom.crypto.service;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.*;
import com.imom.crypto.api.AWSCredential;
import com.imom.crypto.config.Config;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.util.TagsUtils;
import org.apache.log4j.Logger;

import java.util.Base64;
import java.util.List;

public class SecretManagerService {

    private static final Logger log = Logger.getLogger(SecretManagerService.class);
    private static final String TEAM_NAME = "DEC";
    private static final String ERROR = "Error ::: ";
    private String secretNameSuffix;
    private static AWSSecretsManager awsSecretsManager;

    public static void init() {
        String region = Config.getSecretsManagerAWSRegion();
        awsSecretsManager = AWSSecretsManagerClientBuilder.standard()
                .withCredentials(new ClasspathPropertiesFileCredentialsProvider()).withRegion(region).build();
    }

    public AWSSecretsManager getclient(AWSCredential awsCredential, String region) {
        return AWSSecretsManagerClientBuilder.standard().withRegion(region)
                .withCredentials(new AWSStaticCredentialsProvider(new AWSCredentials() {

                    @Override
                    public String getAWSSecretKey() {
                        return awsCredential.getSecretKey();
                    }

                    @Override
                    public String getAWSAccessKeyId() {
                        return awsCredential.getAccessKey();
                    }
                })).build();
    }

    public AWSSecretsManager getClient(String tenantId) {
        AWSCredential data = DBManager.getCredential(tenantId);
        String region = null;
        if (data != null) {
            if (data.getAwsRegion() != null) {
                region = data.getAwsRegion();
            }
            return getclient(data, region);
        }
        return awsSecretsManager;
    }

    public AWSSecretsManager getClient() {
        return awsSecretsManager;
    }

    /***
     * creates a new secret in aws secrets-manager.
     *
     * @param tenantId     refNum/tenantId of the secret
     * @param secretString value of the secret
     */
    public void createSecret(String tenantId, String secretString) {
        try {
            secretNameSuffix = Config.getSecretNameSuffix();
            String env = Config.getEnv();
            env = env.toUpperCase();
            AWSSecretsManager client = getClient(tenantId);
            String secretName = tenantId;
            if (!tenantId.endsWith(secretNameSuffix) || !tenantId.startsWith(TEAM_NAME)) {
                secretName = TEAM_NAME + "/" + env + "/" + tenantId + secretNameSuffix;
            }

            CreateSecretRequest createSecretRequest = new CreateSecretRequest();
            createSecretRequest.setName(secretName);
            createSecretRequest.setDescription("secret for " + tenantId + " created using java application");

            createSecretRequest.setTags(TagsUtils.getSecreteManagerTags());

            createSecretRequest.setSecretString(secretString);

            CreateSecretResult createSecretResult = null;
            try {
                createSecretResult = client.createSecret(createSecretRequest);
                log.info("created secret " + createSecretResult.getName() + " : " + createSecretResult.toString());
            } catch (Exception e) {
                log.error("Error creating secret for " + tenantId + " ::: " + e.getMessage(), e);
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
        }
    }

    /**
     * lists all the secrets.
     */
    public void listSecrets() {
        try {
            AWSSecretsManager client = getClient();
            log.info(" shhhh!! listing secrets!! won't be secret anymore? :P ");
            ListSecretsRequest listSecretsRequest = new ListSecretsRequest();
            ListSecretsResult listSecretsResult = null;
            String nextToken = null;
            int count = 1;
            do {
                log.info("list-iteration-" + (count++));
                try {
                    listSecretsResult = client.listSecrets(listSecretsRequest);
                    List<SecretListEntry> secretsList = listSecretsResult.getSecretList();
                    log.info("secretsList : " + secretsList.toString());
                    nextToken = listSecretsResult.getNextToken();
                    listSecretsRequest.setNextToken(nextToken);
                } catch (Exception e) {
                    log.error("Error listing secrets ::: " + e.getMessage(), e);
                }
            } while (nextToken != null);
        } catch (Exception e) {
            log.error("Error listing secrets ::: " + e.getMessage(), e);
        }
    }

    /**
     * @param tenantId refNum/tenantId of the secret to fetch
     * @return value of the secret
     */
    public String getSecret(String tenantId) {
        try {
            secretNameSuffix = Config.getSecretNameSuffix();
            String env = Config.getEnv().toUpperCase();
            AWSSecretsManager client = getClient(tenantId);
            String secretName = tenantId;
            if (DBManager.getCredential(tenantId) != null && DBManager.getCredential(tenantId).getSecretName() != null) {
                secretName = DBManager.getCredential(tenantId).getSecretName();
            } else if (!tenantId.endsWith(secretNameSuffix) || !tenantId.startsWith(TEAM_NAME)) {
                secretName = TEAM_NAME + "/" + env + "/" + tenantId + secretNameSuffix;
            }

            GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId(secretName);
            GetSecretValueResult getSecretValueResult = null;
            try {
                getSecretValueResult = client.getSecretValue(getSecretValueRequest);
            } catch (DecryptionFailureException | InternalServiceErrorException | InvalidParameterException
                    | InvalidRequestException | ResourceNotFoundException e) {
                log.error(ERROR + " for " + secretName + e.getMessage(), e);
                return null;
            } catch (Exception e) {
                log.error(ERROR + " for " + secretName, e);
                return null;
            }

            // Decrypts secret using the associated KMS CMK.
            // Depending on whether the secret is a string or binary, one of these fields
            // will be populated.
            if (getSecretValueResult.getSecretString() != null) {
                return getSecretValueResult.getSecretString();
            } else {
                return new String(Base64.getDecoder().decode(getSecretValueResult.getSecretBinary()).array());
            }
        } catch (Exception e) {
            log.error(ERROR + e.getMessage(), e);
            return null;
        }
    }

    public void updateSecret(String tenantId, String secretString) {
        String env = Config.getEnv().toUpperCase();
        secretNameSuffix = Config.getSecretNameSuffix();
        String secretName = tenantId;
        AWSSecretsManager client = getClient(tenantId);
        if (!tenantId.endsWith(secretNameSuffix) || !tenantId.startsWith(TEAM_NAME))
            secretName = TEAM_NAME + "/" + env + "/" + tenantId + secretNameSuffix;

        UpdateSecretRequest updateSecretRequest = new UpdateSecretRequest();
        updateSecretRequest.setSecretId(secretName);
        updateSecretRequest.setSecretString(secretString);

        UpdateSecretResult updateSecretResult = null;
        try {
            updateSecretResult = client.updateSecret(updateSecretRequest);
            log.info("updated secret " + updateSecretResult.getName() + " : " + updateSecretResult.toString());
        } catch (Exception e) {
            log.error("Error updating secret for " + tenantId + " ::: " + e.getMessage(), e);
        }
    }

    public void deleteSecrete(String tenantId,String keyId) {
        String env = Config.getEnv().toUpperCase();
        secretNameSuffix = Config.getSecretNameSuffix();
        String secretName = keyId;
        AWSSecretsManager client = getClient(tenantId);
        if (!keyId.endsWith(secretNameSuffix) || !keyId.startsWith(TEAM_NAME))
            secretName = TEAM_NAME + "/" + env + "/" + keyId + secretNameSuffix;

        DeleteSecretRequest deleteSecretRequest = new DeleteSecretRequest().withSecretId(secretName);

        DeleteSecretResult deleteSecretResult  = null;
        try {
            deleteSecretResult = client.deleteSecret(deleteSecretRequest);
            log.info("deleted secret " + deleteSecretResult.getName() + " : " + deleteSecretRequest.toString());
        } catch (Exception e) {
            log.error("Error deleting secret for " + tenantId + " ::: " + e.getMessage(), e);
        }

    }
}
