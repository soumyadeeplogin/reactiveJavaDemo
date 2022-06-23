package com.imom.crypto.controller;

import static com.imom.crypto.util.Constants.ACCESS_KEY;
import static com.imom.crypto.util.Constants.CRYPTO_ERROR;
import static com.imom.crypto.util.Constants.CRYPTO_KEY_NOT_FOUND;
import static com.imom.crypto.util.Constants.DECRYPT;
import static com.imom.crypto.util.Constants.ENCRYPT;
import static com.imom.crypto.util.Constants.ERROR;
import static com.imom.crypto.util.Constants.EXTERNAL;
import static com.imom.crypto.util.Constants.INVALID_JSON_OBJECT;
import static com.imom.crypto.util.Constants.JSON;
import static com.imom.crypto.util.Constants.PRODUCT;
import static com.imom.crypto.util.Constants.PRODUCT_NOT_FOUND;
import static com.imom.crypto.util.Constants.REGION;
import static com.imom.crypto.util.Constants.REQUESTORUSERID;
import static com.imom.crypto.util.Constants.REQUEST_MAP;
import static com.imom.crypto.util.Constants.RESPONSE_CODE;
import static com.imom.crypto.util.Constants.RESPONSE_MAP;
import static com.imom.crypto.util.Constants.SECRET_KEY;
import static com.imom.crypto.util.Constants.SECRET_NAME;
import static com.imom.crypto.util.Constants.SOURCE;
import static com.imom.crypto.util.Constants.STRING;
import static com.imom.crypto.util.Constants.TENANT_ID;
import static com.imom.crypto.util.Constants.TIMETAKEN_FOR;
import static com.imom.crypto.util.Constants.TRUE_VALUE;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;

import com.amazonaws.services.kms.model.OriginType;
import com.imom.crypto.api.CryptoRequest;
import com.imom.crypto.api.CryptoResponse;
import com.imom.crypto.config.AzureConfigLoader;
import com.imom.crypto.config.Config;
import com.imom.crypto.config.Credentials;
import com.imom.crypto.config.PlatformConfig;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.manager.KMSKeys;
import com.imom.crypto.manager.KeyManager;
import com.imom.crypto.service.CryptoService;
import com.imom.crypto.service.SecretManagerService;
import com.imom.crypto.service.jsonHandler;
import com.imom.crypto.util.HttpConnectV2;
import com.imom.crypto.util.HttpConnection;
import com.imom.crypto.util.KeyGen;
import com.imom.crypto.util.MailUtils;
import com.imom.crypto.util.PasswordGenerator;
//import com.sun.jersey.spi.resource.Singleton;
import com.sun.jersey.core.header.FormDataContentDisposition;
import com.sun.jersey.multipart.FormDataParam;
import org.springframework.context.annotation.Scope;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * Controller for CryptoService
 */

@Scope("singleton")
//@Path("/V1.1")
@RestController
@CrossOrigin(origins = "*")
public class CryptoController {

    CryptoService cryptoService;

    public CryptoController() {
        try {
            HttpConnection.init();
            HttpConnectV2.init();
            KeyGen.init();
            Config.init();
            PlatformConfig.init();
            if ("KEYVAULT".equals(PlatformConfig.getvalue())) {
                AzureConfigLoader.init();
                Credentials.init();
            }
            if (Boolean.parseBoolean(Config.getUseSecretsManager())) {
                SecretManagerService.init();
            }
            DBManager.init();
            cryptoService = new CryptoService();
        } catch (Exception ex) {
            log.error("ERROR "+ex.getMessage(),ex);
        }
    }

    private final Logger log = Logger.getLogger(CryptoController.class);
    private final Object lock = new Object();

    /**
     * This End point will encrypt data
     *
     * @return CryptoResponse
     * @paramrequest , CryptoRequest with map of key value pairs of data for which
     * the encryption needs to be done and tenantId
     * @see CryptoResponse
     */

    @PostMapping(path = "/encrypt", consumes = org.springframework.http.MediaType.APPLICATION_JSON_VALUE, produces = org.springframework.http.MediaType.APPLICATION_JSON_VALUE)
    public Response encrypt(String str) {
        return encryptDecrypt(str, ENCRYPT, JSON, null);
    }

    /**
     * This End point will decrypt data
     *
     * @return CryptoResponse
     * @throws JSONException
     * @paramrequest , CryptoRequest with map of key value pairs of data for which
     * the decryption needs to be done and tenantId
     * @see CryptoResponse
     */

    @PostMapping(path = "/decrypt", consumes = org.springframework.http.MediaType.APPLICATION_JSON_VALUE, produces = org.springframework.http.MediaType.APPLICATION_JSON_VALUE)
    public Response decrypt(String str) {
        return encryptDecrypt(str, DECRYPT, JSON, null);
    }


    @Path("/reload")
    @GET
    @Produces({MediaType.APPLICATION_JSON})

    @GetMapping(path = "/reload", produces = org.springframework.http.MediaType.)
    public Response reload() {
        log.info("starting reload method");
        Response response = null;
        synchronized (lock) {
            response = DBManager.reloadMaps();
        }
        log.info("ending reload method");
        return response;
    }

    @Path("/getClientStatus")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getClient(String str) {
        synchronized (lock) {

            DBManager.reloadMaps();
            JSONObject jsobj = new JSONObject(str);
            String tenantId = jsobj.getString(TENANT_ID);
            if (DBManager.getCmks(tenantId) != null) {
                log.warn("tenantId exists");
                return Response.status(Response.Status.OK).entity("tenantId exists").build();
            } else {
                log.warn("tenantId not exists");
                return Response.status(Response.Status.OK).entity("tenantId not exists").build();
            }
        }
    }

    @Path("/addclient")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response addClient(String str) {
        Response response = null;
        JSONObject body = new JSONObject();
        synchronized (lock) {
            DBManager.reloadMaps();
            JSONObject jsobj = new JSONObject(str);
            String tenantId = jsobj.getString(TENANT_ID);
            if (TRUE_VALUE.equals(Config.getTenantCheck())) {
                HashSet<String> tenants = HttpConnection.getClientList(Config.getCMSApi());
                if (!tenants.contains(tenantId)) {
                    log.warn("Incorrect tenantId");
                    return Response.status(Response.Status.BAD_REQUEST).entity("Incorrect tenantId").build();
                }
            }
            byte[] password = null;
            byte[] salt = null;
            if (jsobj.has("password") && jsobj.has("salt")) {
                password = jsobj.getString("password").getBytes();
                salt = jsobj.getString("salt").getBytes();
            } else {
                password = PasswordGenerator.generateStrongPassword().getBytes();
                salt = PasswordGenerator.generateStrongPassword().getBytes();
            }
            body.put("refNum", tenantId);
            body.put("Env", Config.getEnv());
            body.put("password", password);
            body.put("salt", salt);

            String accessKey = jsobj.optString(ACCESS_KEY);
            String secretKey = jsobj.optString(SECRET_KEY);
            String secretName = jsobj.optString(SECRET_NAME);
            String awsRegion = jsobj.optString(REGION);

            // basic null check
            if (tenantId == null || "".equals(tenantId)) {
                log.warn("tenantId null");
                return Response.status(Response.Status.BAD_REQUEST).entity("tenantId null").build();
            }
            // check if this tenant is present in db or not
            if (KeyManager.getKey(tenantId) != null) {
                log.warn("tenantId already exists");
                return Response.status(Response.Status.BAD_REQUEST).entity("tenantId already exists").build();
            }

            if (accessKey.trim().isEmpty() && secretKey.trim().isEmpty()) {
                log.warn("tenantId donot have accessskey and secretkey");
            } else if (accessKey.trim().isEmpty() || secretKey.trim().isEmpty()) {
                log.warn("tenantId only have either accessskey and secretkey");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("tenantId only have either accessskey and secretkey").build();
            } else {
                if ("".equals(awsRegion)) {
                    log.warn("tenantId donot have region");
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("tenantId donot have region").build();
                }
            }

            if ("".equals(secretName)) {
                log.info("tenantId donot have secretname");
            }

            //call insert keymanager
            String keyManagerPassword = DBManager.getKeyManagerPassword();
            if (!accessKey.trim().isEmpty() && !secretKey.trim().isEmpty()) {
                KeyGen.insertKeyManager(tenantId, Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(),
                        keyManagerPassword, secretKey.getBytes(), accessKey.getBytes(), secretName.getBytes(), awsRegion.getBytes());
            }

            // call insert key
            String keyPassword = DBManager.getKeyPassword();
            KeyGen.insertKey(tenantId, Config.getKeyUrl(), Config.getKeyUserNamel(), keyPassword);
            // call create salt
            String passPassword = DBManager.getPassword();
            KeyGen.createSalt(tenantId, password, salt, Config.getPassUrl(), Config.getPassUserNamel(), passPassword,
                    Config.getKeyUrl(), Config.getKeyUserNamel(), keyPassword);
        }
        // call reload
        log.info("starting hitLBNodes method");
        if(Config.getV2deployment())
            response = HttpConnectV2.hitLBNodes();
        else response = HttpConnection.hitLBNodes();
        log.info("ending hitLBNodes method");

        // return successful response
        if (response.getStatus() != 200) {
            return response;
        }
        log.info("successfully added new client");
        MailUtils.sendSimpleEmail(Config.getUsername(), Config.getPassword(), Config.getEmailId(), Config.getMailSMTPHost(), Config.getMailSMTPPort(), Config.getMailSMTPAuth(), Config.getMailSMTPEnable(), body);
        return Response.status(Response.Status.OK).entity("successfully added new client").build();
    }

    @Path("/byok")
    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces({MediaType.APPLICATION_JSON})
    public Response byok(@Context HttpServletRequest req,@FormDataParam("keyfile") InputStream is,
                         @FormDataParam("keyfile") FormDataContentDisposition fileDetail,
                         @FormDataParam("tenantId") String tenantId,
                         @FormDataParam("requestorUserId") String requestorUserId,
                         @FormDataParam("source") String source) throws IOException, ServletException {

        log.info("tenantId "+tenantId);
        log.info("requestorUserId "+requestorUserId);
        log.info("source "+source);
        log.info("fileDetail "+fileDetail.getFileName());

        byte[] plainTextKey = IOUtils.toByteArray(is);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(TENANT_ID,tenantId);
        jsonObject.put(REQUESTORUSERID,requestorUserId);
        jsonObject.put(SOURCE,source);
        jsonObject.put("plainTextKey",Base64.getEncoder().encodeToString(plainTextKey));

        addClinetV2(req,jsonObject.toString());
        log.info("PRINTING FILE\n\n"+ Base64.getEncoder().encodeToString(plainTextKey)+"\n\n\n END OF FILE");

        return Response.status(Response.Status.OK).build();

    }

    @Path("/addclient_v2")
    @POST
    @Produces({MediaType.APPLICATION_JSON})
    public Response addClinetV2(@Context HttpServletRequest req, String str) {
        Response response = null;
        KMSKeys resp;
        synchronized (lock) {
            DBManager.reloadMaps();
            KMSKeys kmsKeys = new KMSKeys();
            JSONObject jsobj = new JSONObject(str);

            //null check fot tenantId
            if (!jsobj.has(TENANT_ID) || "".equals(jsobj.getString(TENANT_ID))) {
                log.warn("tenantId null");
                return Response.status(Response.Status.BAD_REQUEST).entity("tenantId null").build();
            }

            //tenantId exits check
            if (DBManager.getCmks(jsobj.getString(TENANT_ID)) != null) {
                log.warn("tenantId already exists");
                return Response.status(Response.Status.BAD_REQUEST).entity("tenantId already exists").build();
            }

            //Invalid tenantId check
            if (TRUE_VALUE.equals(Config.getTenantCheck())) {
                HashSet<String> tenants = HttpConnection.getClientList(Config.getCMSApi());
                if (!tenants.contains(jsobj.getString(TENANT_ID))) {
                    log.warn("Incorrect tenantId");
                    return Response.status(Response.Status.BAD_REQUEST).entity("Incorrect tenantId").build();
                }
            }

            //requestor user id check
            if (!jsobj.has(REQUESTORUSERID) ||  "".equals(jsobj.getString(REQUESTORUSERID)) ) {
                log.warn("requestorUserId null / requestorUserId is not present");
                return Response.status(Response.Status.BAD_REQUEST).entity("requestorUserId is null / requestorUserId is not present").build();
            }

            //get the source
            if (jsobj.has(SOURCE))
                kmsKeys.setSources(jsobj.getString(SOURCE));

            //if source is not present consider internal
            if (kmsKeys.getSources() == null) {
                log.info("Source is null / source is not present for "+jsobj.getString(TENANT_ID));
                kmsKeys.setSources(OriginType.AWS_KMS.toString());
            }

            //source value check
            if (!EXTERNAL.equals(kmsKeys.getSources()) && ! OriginType.AWS_KMS.toString().equals(kmsKeys.getSources())) {
                log.warn("incorrect source");
                return Response.status(Response.Status.BAD_REQUEST).entity("incorrect source (EXTERNAL/AWS_KMS)").build();
            }

            kmsKeys.setPlaintextKey(null);

            if(kmsKeys.getSources() != null && jsobj.has("plainTextKey")) {
                kmsKeys.setPlaintextKey(Base64.getDecoder().decode(jsobj.getString("plainTextKey")));
            }

            kmsKeys.setTenantId(jsobj.getString(TENANT_ID));
            kmsKeys.setUser(jsobj.getString(REQUESTORUSERID));
            kmsKeys.setIpAddress(req.getRemoteAddr());

            resp = KeyGen.insertCmk(kmsKeys);
        }

        if(resp != null) {
            log.info("starting hitLBNodes method");
            if(Config.getV2deployment())
                response = HttpConnectV2.hitLBNodes();
            else response = HttpConnection.hitLBNodes();
            log.info("ending hitLBNodes method");
            // return successful response
            if (response.getStatus() != 200) {
                return response;
            }
            log.info("successfully added new client");
            return  Response.status(Response.Status.OK).entity("successfully added new client").build();
        }
        return  Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("something went wrong while creating the kms").build();
    }



    @Path("/migratecmks")
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    public Response migrateCmks(@Context HttpServletRequest request) {
        synchronized (lock) {
            DBManager.reloadMaps();
            KeyGen.migrateTenants(request.getRemoteAddr());
            DBManager.reloadMaps();
            log.info("successfully migrated all clients");
            return Response.status(Response.Status.OK).entity("successfully migrated all clients").build();
        }
    }

    @Path("/reloadall")
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    public Response reloadlb() {
        boolean v2Deployment = Config.getV2deployment();
        if(v2Deployment)
            return HttpConnectV2.hitLBNodes();
        return HttpConnection.hitLBNodes();
    }

    @Path("/encryptstring")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response encryptString(String str) {
        return encryptDecrypt(str, ENCRYPT, STRING, null);
    }

    @Path("/decryptstring")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response decryptString(String str) {
        return encryptDecrypt(str, DECRYPT, STRING, null);
    }

    /**
     * This End point will encrypt data for internal purposes
     *
     * @return CryptoResponse
     * @paramrequest CryptoRequest with map of key value pairs of data for which
     * the encryption needs to be done and tenantId
     * @see CryptoResponse
     */
    @Path("/encryptinternal")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response encryptInternal(String str) {
        return encryptDecrypt(str, ENCRYPT, JSON, "encryptRequest");
    }

    /**
     * This End point will decrypt data for internal purposes.
     *
     * @return CryptoResponse
     * @throws JSONException
     * @paramrequest CryptoRequest with map of key value pairs of data for which
     * the decryption needs to be done and tenantId
     * @see CryptoResponse
     */

    @Path("/decryptinternal")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response decryptInternal(String str) {
        return encryptDecrypt(str, DECRYPT, JSON, "decryptRequest");
    }


    public Response encryptDecrypt(String str, String mode, String type, String source) {

        CryptoRequest request = new CryptoRequest();
        JSONObject jsobj = null;
        JSONObject resobj = new JSONObject();
        HashMap<String, String> hm = new HashMap<>();
        try {
            jsobj = new JSONObject(str);
            if ((TRUE_VALUE.equals(Config.getProductEnable())) && !jsobj.has(PRODUCT)) {
                resobj.put(ERROR, PRODUCT_NOT_FOUND);
                return Response.status(Response.Status.BAD_REQUEST).entity(resobj.toString()).build();
            }
            if (source != null) {
                if (!cryptoService.getCommonKeysList().contains(jsobj.getString("key"))) {
                    log.error("Error : The key doesn't exist" + " : REQUEST from product : " + jsobj.optString(PRODUCT, "null"));
                    resobj.put(ERROR, CRYPTO_KEY_NOT_FOUND);
                    return Response.status(Response.Status.BAD_REQUEST).entity(resobj.toString()).build();
                }
                request.setTenantId(jsobj.getString("key"));
            } else
                request.setTenantId(jsobj.getString(TENANT_ID));
            if (type.equals(JSON)) {
                JSONObject temp;
                if (source != null)
                    temp = (JSONObject) jsobj.get(source);
                else temp = (JSONObject) jsobj.get(REQUEST_MAP);
                Iterator<String> itr = temp.keys();
                while (itr.hasNext()) {
                    String key = itr.next();
                    hm.put(key, temp.get(key).toString());
                }
            } else
                hm.put(REQUEST_MAP, jsobj.get(REQUEST_MAP).toString());
        } catch (JSONException e) {
            resobj.put(ERROR, INVALID_JSON_OBJECT);
            return Response.status(Response.Status.BAD_REQUEST).entity(resobj.toString()).build();
        }
        request.setRequestMap(hm);
        long startTime = System.currentTimeMillis();
        CryptoResponse response = cryptoService.encrypt_decrypt(request, mode, type);
        long timeTaken = System.currentTimeMillis() - startTime;
        log.debug(TIMETAKEN_FOR + mode + timeTaken);
        // Checking response code to find out error
        if (response.getResponseCode() == -1) {
            resobj.put(ERROR, CRYPTO_ERROR);
            if (source != null)
                log.error(CRYPTO_ERROR + " : INAVALID REQUEST" + " : REQUEST from product : " + jsobj.optString(PRODUCT, "null"));
            else
                log.error(CRYPTO_ERROR + " : INAVALID REQUEST for tenant : " + jsobj.getString(TENANT_ID) + " : REQUEST from product : " + jsobj.optString(PRODUCT, "null"));
            return Response.status(Response.Status.BAD_REQUEST).entity(resobj.toString()).build();
        } else if (response.getResponseCode() == -2) {
            resobj.put(ERROR, CRYPTO_KEY_NOT_FOUND);
            if (source != null)
                log.error(CRYPTO_KEY_NOT_FOUND + " : INAVALID REQUEST" + " : REQUEST from product : " + jsobj.optString(PRODUCT, "null"));
            else
                log.error(CRYPTO_KEY_NOT_FOUND + " : INAVALID REQUEST for tenant : " + jsobj.getString(TENANT_ID) + " : REQUEST from product : " + jsobj.optString(PRODUCT, "null"));

            return Response.status(Response.Status.BAD_REQUEST).entity(resobj.toString()).build();
        }
        // Response Code
        resobj.put(RESPONSE_CODE, response.getResponseCode());
        JSONObject responseJson = new JSONObject();
        Map<String, String> respmap = response.getResponseMap();
        Iterator<String> responseIt = respmap.keySet().iterator();
        while (responseIt.hasNext()) {
            String key = responseIt.next();
            String value = respmap.get(key);
            if (type.equals(JSON)) {
                if (jsonHandler.validateNestedJSonObject(value)) {
                    JSONObject obj = jsonHandler.jsonConverter(value);
                    responseJson.put(key, obj);
                } else if (jsonHandler.validateJSonArray(value)) {
                    JSONObject tempJson = new JSONObject();
                    tempJson.put(key, value);
                    JSONObject obj = jsonHandler.jsonConverter(tempJson.toString());
                    tempJson.remove(key);
                    Iterator<String> tmpItr = obj.keys();
                    while (tmpItr.hasNext()) {
                        String tkey = tmpItr.next();
                        responseJson.put(tkey, obj.get(tkey));
                        break; // no need
                    }
                } else
                    responseJson.put(key, value);
            } else responseJson.put(key, value);
        }
        resobj.put(RESPONSE_MAP, responseJson);

        return Response.status(Response.Status.OK).entity(resobj.toString()).build();
    }

}
