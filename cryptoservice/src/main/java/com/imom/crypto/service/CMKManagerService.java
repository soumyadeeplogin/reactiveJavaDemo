package com.imom.crypto.service;

import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;
import com.imom.crypto.config.Config;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.manager.KMSKeys;
import com.imom.crypto.util.KeyGen;
import com.imom.crypto.util.RSAUtils;
import com.imom.crypto.util.TagsUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.JsonNodeFactory;
import org.codehaus.jackson.node.ObjectNode;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import static com.imom.crypto.util.Constants.*;

public class CMKManagerService {

    private static final Logger log = Logger.getLogger(CMKManagerService.class);
    private final AWSKMS kmsClient;

    public CMKManagerService() {
        String region =  Config.getSecretsManagerAWSRegion();
        this.kmsClient = AWSKMSClientBuilder.standard().withCredentials(new ClasspathPropertiesFileCredentialsProvider()).withRegion(region).build();
    }

    public KMSKeys createCmsk(KMSKeys request) {
        try {
            //Create KMS
            KMSKeys kmsKeys = createKMS(request);

            if(kmsKeys != null) {

                //Request to generate data key
                GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest().withKeyId(kmsKeys.getKeyId()).withKeySpec(DataKeySpec.AES_256);

                GenerateDataKeyResult generateDataKeyResult = kmsClient.generateDataKey(generateDataKeyRequest);

                log.info("DEK is generated successfully for "+request.getTenantId());
                log.info("keyID for generated DEK "+request.getKeyId());

                //get ciphertext blob -> encrypted data key with mata-data
                byte[] dataKey = generateDataKeyResult.getCiphertextBlob().array();

                SecretManagerService secretManagerService = new SecretManagerService();

                String datakeyString = Base64.encodeBase64String(dataKey);
                //Store encrypted and plaintext in secrete manager with refnum
                ObjectNode secretNode = JsonNodeFactory.instance.objectNode();
                secretNode.put(REFNUM, request.getTenantId());
                secretNode.put(KEY, datakeyString);
                if(request.getSources().equals(EXTERNAL))
                    secretNode.put(PLAINTEXT,Base64.encodeBase64String(kmsKeys.getPlaintextKey()));
                secretManagerService.createSecret(request.getTenantId()+CMK, secretNode.toString());
                log.info("encrypted DEK is stored into secrete manager successfully for "+request.getTenantId());
                return kmsKeys;
            }
        } catch (Exception ex) {
            log.error("Error creating cmk ::: " + ex.getMessage(), ex);
            return null;
        }
        return null;
    }

    public KMSKeys rotateCmsk(KMSKeys kmsKeys, String dbPwd) {
        try {
            KMSKeys newKmsKeys;
            ObjectNode secretNode;
            ObjectMapper objectMapper = new ObjectMapper();
            SecretManagerService secretManagerService = new SecretManagerService();
            // get encrypted key from secrete manager
            String secret = secretManagerService.getSecret(kmsKeys.getTenantId()+"_CMK");
            String key = null;
            if (secret != null) {
                secretNode = (ObjectNode) objectMapper.readTree(secret);
                if (secretNode.size() > 0 && secretNode.has("key") && secretNode.get("key") != null)
                    key = secretNode.get("key").asText();
                else  log.error("key is not present or null for " + kmsKeys.getTenantId());
            } else {
                log.error("Error ::: " + kmsKeys.getTenantId() + " is null in SecretsManager");
            }
            if (key != null) {
                log.info("successfully got the encrypted from secrete manager for "+kmsKeys.getTenantId());
                byte[] decodeBase64 = Base64.decodeBase64(key);
                String source =  DBManager.getCmks(kmsKeys.getTenantId()).getSources();
                kmsKeys.setSources(source);
                //create new KMS for rotating key
                newKmsKeys = createKMS(kmsKeys);

                if(newKmsKeys != null) {
                    //re-encrypt the encrypted key
                    ReEncryptRequest reEncryptRequest = new ReEncryptRequest().withCiphertextBlob(ByteBuffer.wrap(decodeBase64)).withDestinationKeyId(newKmsKeys.getKeyId());
                    ReEncryptResult reEncryptResult = kmsClient.reEncrypt(reEncryptRequest);

                    log.info("key is re-encrypted successfully for "+kmsKeys.getTenantId());

                    String datakeyString = Base64.encodeBase64String(reEncryptResult.getCiphertextBlob().array());
                    secretNode = JsonNodeFactory.instance.objectNode();
                    secretNode.put(REFNUM, kmsKeys.getTenantId());
                    secretNode.put(KEY, datakeyString);
                    if(source.equals(EXTERNAL))
                       secretNode.put(PLAINTEXT, Base64.encodeBase64String(newKmsKeys.getPlaintextKey()));
                    //Update encrypted key and plaintext key with refum
                    secretManagerService.updateSecret(kmsKeys.getTenantId()+CMK, secretNode.toString());

                    log.info("key is updated successfully in secrete manager for "+kmsKeys.getTenantId());

                    //disable old KMS
                    DisableKeyRequest disableKeyRequest = new DisableKeyRequest().withKeyId(DBManager.getCmks(kmsKeys.getTenantId()).getKeyId());
                    kmsClient.disableKey(disableKeyRequest);

                    log.info("key is disabled successfully for "+kmsKeys.getTenantId());

                    //Stored last plaintext key to secrete manager (last 3)
                    if(source.equals(EXTERNAL)) {
                        secretNode = JsonNodeFactory.instance.objectNode();
                        secretNode.put("refNum", kmsKeys.getTenantId());
                        secretNode.put("plainText",  Base64.encodeBase64String(newKmsKeys.getPlaintextKey()));
                        secretManagerService.createSecret(DBManager.getCmks(kmsKeys.getTenantId()).getKeyId(), secretNode.toString());
                        log.info("key material is stored successfully in secrete manager for "+kmsKeys.getTenantId());
                    }

                    KMSKeys oldKmskeys = new KMSKeys();
                    oldKmskeys.setTenantId(kmsKeys.getTenantId());
                    oldKmskeys.setKeyId(DBManager.getCmks(kmsKeys.getTenantId()).getKeyId());
                    oldKmskeys.setUser(kmsKeys.getUser());
                    oldKmskeys.setIpAddress(kmsKeys.getIpAddress());

                    //update old KMS status as inactive to db
                    KeyGen.updateCmkStatus(oldKmskeys, dbPwd);
                    //audit the logs as old is disabled
                    KeyGen.auditlog(oldKmskeys,DISABLED,dbPwd);
                    //keeping last 3 secrete and KMS, after that deleting KMS and secrete
                    KeyGen.deleteCMk(oldKmskeys, dbPwd);

                    return newKmsKeys;
                }
            } else {
                log.error("key is not present for " +kmsKeys.getTenantId() );
                return null;
            }
        } catch (Exception ex) {
            log.error("Error rotating cmk ::: " + ex.getMessage(), ex);
            return null;

        }
        return null;
    }

    public KMSKeys migrateKMS(String tenantId, String source,byte[] key) {
        KMSKeys request = new KMSKeys();
        request.setTenantId(tenantId);
        request.setSources(source);
        KMSKeys kmsKeys = createKMS(request);
        SecretManagerService secretManagerService = new SecretManagerService();
        if(kmsKeys != null) {
            EncryptRequest encryptRequest = new EncryptRequest().withKeyId(kmsKeys.getKeyId()).withPlaintext(ByteBuffer.wrap(key));
            EncryptResult encryptResult = kmsClient.encrypt(encryptRequest);
            String datakeyString = Base64.encodeBase64String(encryptResult.getCiphertextBlob().array());
            ObjectNode secretNode = JsonNodeFactory.instance.objectNode();
            secretNode.put(REFNUM, tenantId);
            secretNode.put(KEY, datakeyString);
            String serviceSecret = secretManagerService.getSecret(tenantId+CMK);
            if (serviceSecret != null)
                secretManagerService.updateSecret(tenantId+CMK,secretNode.toString());
            else secretManagerService.createSecret(tenantId+CMK, secretNode.toString());
        }
        return kmsKeys;
    }

    private KMSKeys createKMS(KMSKeys request) {
        try {
            String desc = "KMS for " + request.getTenantId();
            KMSKeys kmsKeys = new KMSKeys();

            CreateKeyRequest createKeyRequest;
            if (EXTERNAL.equals(request.getSources()))
                createKeyRequest = new CreateKeyRequest().withOrigin(OriginType.EXTERNAL).withDescription(desc).withTags(TagsUtils.getKMSTags());
            else
                createKeyRequest = new CreateKeyRequest().withOrigin(OriginType.AWS_KMS).withDescription(desc).withTags(TagsUtils.getKMSTags());

            CreateKeyResult kmsClientKey = kmsClient.createKey(createKeyRequest); //key is created

            log.info("CMK is created successfully for "+request.getSources());

            kmsKeys.setKeyId(kmsClientKey.getKeyMetadata().getKeyId());
            kmsKeys.setArn(kmsClientKey.getKeyMetadata().getArn());
            kmsKeys.setTenantId(request.getTenantId());
            kmsKeys.setSources(request.getSources());

            //if source is EXTERNAL then we need to import key material to KMS
            if (EXTERNAL.equals(request.getSources())) {
                byte[] plainTextKey = null;

                if(request.getPlaintextKey() != null)
                    plainTextKey = request.getPlaintextKey();  //if key plaintext from request
                else {
                    // Generate plaintext key
                    KeyGenerator keyGen;
                    keyGen = KeyGenerator.getInstance(AES);
                    keyGen.init(256);
                    SecretKey secretKey = keyGen.generateKey();
                    plainTextKey = secretKey.getEncoded();
                }

                kmsKeys.setPlaintextKey(plainTextKey);

                //request to get public key and import token
                GetParametersForImportRequest getParametersRequest = new GetParametersForImportRequest()
                        .withKeyId(kmsKeys.getKeyId()).withWrappingAlgorithm(Config.getWrappingAlgorithm())
                        .withWrappingKeySpec(WrappingKeySpec.RSA_2048);

                GetParametersForImportResult getParametersResponse = kmsClient.getParametersForImport(getParametersRequest);

                ByteBuffer importToken = getParametersResponse.getImportToken();

                ByteBuffer publicKey = getParametersResponse.getPublicKey();

                RSAPublicKey rsaPublicKey = RSAUtils.X509EncodedKeySpec(publicKey);
                if(rsaPublicKey == null) {
                    log.error("Encoding of public key is failed");
                    return null;
                }
                //encrypt plaintext key with encoded public key
                byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plainTextKey);

                if(encryptedAesKey == null) {
                    log.error("encryption plaintext key with encoded public key is failed");
                    return null;
                }

                //Import key material request with import token and encrypted plaintext key material
                ImportKeyMaterialRequest importRequest = new ImportKeyMaterialRequest().withKeyId(kmsKeys.getKeyId())
                        .withEncryptedKeyMaterial(ByteBuffer.wrap(encryptedAesKey))
                        .withImportToken(importToken)
                        .withExpirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                        .withValidTo(Date.from(Instant.now().plusSeconds(Long.parseLong(Config.getValidTo()))));

                kmsClient.importKeyMaterial(importRequest); //key material is imported

                log.info("key material is imported successfully for "+request.getTenantId());
            }
            log.info("KMS is created successfully for "+request.getTenantId());
            return kmsKeys;
        } catch (Exception ex) {
            log.error("ERROR ::" + ex.getMessage(), ex);
            return null;
        }
    }

    public void scheduleKeyTODelete(String arn) {
       try {
           DescribeKeyResult describeKeyResult = kmsClient.describeKey(new DescribeKeyRequest().withKeyId(arn));
           if(!describeKeyResult.getKeyMetadata().getKeyState().equals("PendingDeletion")) {
               ScheduleKeyDeletionRequest scheduleKeyDeletionRequest = new ScheduleKeyDeletionRequest();
               scheduleKeyDeletionRequest.setPendingWindowInDays(7);
               scheduleKeyDeletionRequest.setKeyId(arn);
               ScheduleKeyDeletionResult scheduleKeyDeletionResult = kmsClient.scheduleKeyDeletion(scheduleKeyDeletionRequest);
               log.info("Deletion key date for " + scheduleKeyDeletionResult.getDeletionDate());
           }
       } catch (Exception ex) {
           log.error("ERROR ::"+ex.getMessage() , ex);
       }
    }

    public byte[] getPlaintextKey(byte[] ciphertextBlob) {
        try {
            DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(ciphertextBlob));
            DecryptResult decrypt = kmsClient.decrypt(decryptRequest);
            return decrypt.getPlaintext().array();
        } catch (Exception ex) {
            log.error("Error getting plaintext from kms ::: " + ex.getMessage(), ex);
            return null;
        }
    }
}
