package com.phenom.cryptoservice.byok;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.CreateSecretRequest;
import com.amazonaws.services.secretsmanager.model.CreateSecretResult;
import com.amazonaws.services.secretsmanager.model.Tag;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

@RestController
public class Controller {

    @Autowired
    Environment env;

    @PostMapping(path = "/byokFileUpload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> byok(@RequestParam("file") MultipartFile file) throws IOException {
        System.out.println("REQ BODY  \n" );
        String out = "";
        String line;
        InputStream is = file.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        while ((line = br.readLine()) != null) {
            out+=line;
        }


        return ResponseEntity.ok().body(out);
    }

    @GetMapping(path = "/getKey")
    public ResponseEntity<Object> getKey()
    {
        System.out.println("getKey");


        //Create Key Without Key Material
        String desc = "Key for protecting critical data";

        String accessKey = env.getProperty("AccessKeyId");
        String secretKey = env.getProperty("SecretAccessKey");
        String region = env.getProperty("region");
        AWSCredentials credential = new BasicAWSCredentials(accessKey, secretKey);



        AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credential))
                .withRegion(region)
                .build();

//        CreateKeyRequest req = new CreateKeyRequest().withOrigin(OriginType.EXTERNAL).withDescription(desc);

//        CreateKeyResult result = kmsClient.createKey(req);

//        System.out.println(result);

//        String keyId = kmsClientKey.getKeyMetadata().getKeyId();
        String keyId = "38b1fc92-a3d9-4a7a-87b6-32ce7f8adaa7";
//        String keyId = "7eda78c0-ccad-4963-8696-e237681dc203";

        GetParametersForImportRequest getParametersRequest = new GetParametersForImportRequest();
        getParametersRequest.setKeyId(keyId);

        getParametersRequest.setWrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_256);
        getParametersRequest.setWrappingKeySpec(WrappingKeySpec.RSA_2048);

        GetParametersForImportResult getParametersResponse = kmsClient.getParametersForImport(getParametersRequest);

        ByteBuffer importToken =  getParametersResponse.getImportToken();
        ByteBuffer publicKey =  getParametersResponse.getPublicKey();



        byte[] plaintextAesKey = new byte[AES_KEY_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(plaintextAesKey);

        System.out.println();

        //From here with us
        RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicKey);
        byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);
        //wrapping done

        ImportKeyMaterialRequest importRequest = new ImportKeyMaterialRequest().withKeyId(keyId)
                .withEncryptedKeyMaterial(ByteBuffer.wrap(encryptedAesKey))
                .withImportToken(importToken)
                .withExpirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                .withValidTo(Date.from(Instant.now().plusSeconds(365*24*60*60)));

        kmsClient.importKeyMaterial(importRequest);

        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest().withKeyId(keyId).withKeySpec(DataKeySpec.AES_256);
        GenerateDataKeyResult generateDataKeyResult = kmsClient.generateDataKey(generateDataKeyRequest);

        //Now we have to store it in secret manager
        //get ciphertext blob -> encrypted data key with mata-data
        byte[] dataKey = generateDataKeyResult.getCiphertextBlob().array();


        AWSSecretsManager awsSecretsManagerus = AWSSecretsManagerClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(credential))
                .withRegion(region)
                .build();


        String datakeyString = Base64.encodeBase64String(dataKey);
        //Store encrypted and plaintext in secrete manager with refnum
        ObjectNode secretNode = JsonNodeFactory.instance.objectNode();
        secretNode.put("REFNUM", "PHENA0059TEST");
        secretNode.put("key", datakeyString);


        createSecret( awsSecretsManagerus,"PHENA0059TEST_CMK", secretNode.toString());
        System.out.println("encrypted DEK is stored into secrete manager successfully for "+ "PHENA0059TEST");


        return ResponseEntity.ok().body("keyId");
    }



    public static List<Tag> getSecreteManagerTags() {
        List<com.amazonaws.services.secretsmanager.model.Tag> tags = new ArrayList<>();
        com.amazonaws.services.secretsmanager.model.Tag teamTag = new com.amazonaws.services.secretsmanager.model.Tag();
        teamTag.setKey("team");
        teamTag.setValue("dec");
        tags.add(teamTag);

        com.amazonaws.services.secretsmanager.model.Tag envTag = new com.amazonaws.services.secretsmanager.model.Tag();
        envTag.setKey("env");
        envTag.setValue("stgir");
        tags.add(envTag);

        com.amazonaws.services.secretsmanager.model.Tag ownerTag = new com.amazonaws.services.secretsmanager.model.Tag();
        ownerTag.setKey("owner");
        ownerTag.setValue("sureshbabu devineni");
        tags.add(ownerTag);

        com.amazonaws.services.secretsmanager.model.Tag ownerEmailTag = new com.amazonaws.services.secretsmanager.model.Tag();
        ownerEmailTag.setKey("owneremail");
        ownerEmailTag.setValue("sureshbabu.devineni@phenompeople.com");
        tags.add(ownerEmailTag);

        com.amazonaws.services.secretsmanager.model.Tag RenewaldateTag = new com.amazonaws.services.secretsmanager.model.Tag();
        RenewaldateTag.setKey("renewaldate");
        RenewaldateTag.setValue((LocalDate.now().getDayOfMonth())+getMonth()+getYear());
        tags.add(RenewaldateTag);

        com.amazonaws.services.secretsmanager.model.Tag CreationdateTag = new com.amazonaws.services.secretsmanager.model.Tag();
        CreationdateTag.setKey("creationdate");
        CreationdateTag.setValue((LocalDate.now().getDayOfMonth())+getMonth()+(LocalDate.now().getYear()));
        tags.add(CreationdateTag);

        com.amazonaws.services.secretsmanager.model.Tag reasonTag = new com.amazonaws.services.secretsmanager.model.Tag();
        reasonTag.setKey("reason");
        reasonTag.setValue("crypto service");
        tags.add(reasonTag);

        com.amazonaws.services.secretsmanager.model.Tag modeuleTad = new com.amazonaws.services.secretsmanager.model.Tag();
        modeuleTad.setKey("module");
        modeuleTad.setValue("dec");
        tags.add(modeuleTad);
        return tags;
    }
    private static String getMonth() {
        return LocalDate.now().getMonth().name().charAt(0) +LocalDate.now().getMonth().name().toLowerCase().substring(1,3);
    }

    private static String getYear() {
        return String.valueOf(LocalDate.now().getYear()+1);
    }

    public void createSecret(AWSSecretsManager awsSecretsManage, String secreteName, String secretNode)
{
        CreateSecretRequest createSecretRequest = new CreateSecretRequest();
        createSecretRequest.setName(secreteName);
        createSecretRequest.setDescription("secret for " + "PHENA0059TEST" + " created using java application");

        createSecretRequest.setTags(getSecreteManagerTags());

        createSecretRequest.setSecretString(secretNode);

        CreateSecretResult createSecretResult = null;
        try {
            createSecretResult = awsSecretsManage.createSecret(createSecretRequest);
            System.out.println("created secret " + createSecretResult.getName() + " : " + createSecretResult.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static final int AES_KEY_SIZE_BYTES = 256/8;
    private static final Random SECURE_RANDOM = new SecureRandom();
}
