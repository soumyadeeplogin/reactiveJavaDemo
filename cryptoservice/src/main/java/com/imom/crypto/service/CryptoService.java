package com.imom.crypto.service;

import com.imom.crypto.api.CryptoRequest;
import com.imom.crypto.api.CryptoResponse;
import com.imom.crypto.api.CryptoResponseCode;
import com.imom.crypto.config.AzureConfigLoader;
import com.imom.crypto.config.PlatformConfig;
import com.imom.crypto.subservice.DBService;
import com.imom.crypto.subservice.KeyVaultService;
import com.imom.crypto.subservice.SubService;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

import static com.imom.crypto.util.Constants.CRYPTO_ERROR;
import static com.imom.crypto.util.Constants.CRYPTO_KEY_NOT_FOUND;

/**
 * Service which encrypts/decrypts data or files
 */

public class CryptoService {

    private SubService subserviceobj = null;
    private final List<String> commonKeysList = new ArrayList<>();

    public CryptoService() {

        String plt = PlatformConfig.getvalue();
        if (plt.equals("AWS")) {
            subserviceobj = new DBService();
        } else if (plt.equals("KEYVAULT")) {
            subserviceobj = new KeyVaultService();
            String commonKeys = AzureConfigLoader.getCommonKeys();
            String[] commonKeysArray = commonKeys.split(",");
            Collections.addAll(commonKeysList, commonKeysArray);
        }
    }

    // Recursive Encryption
    public JSONObject jsonEncryptDecrypt(JSONObject obj, String tenantid, String mode) {

        //outMap -> EncryptedMap or PlaintextMap
        Map<String, String> outputMap = new HashMap<>();

        JSONObject response_json = new JSONObject();

        Iterator<String> itr = obj.keys();

        while (itr.hasNext()) {
            String key = itr.next();
            String value = obj.get(key).toString();

            //Checking if it is nested JSON or not
            if (jsonHandler.validateNestedJSonObject(value)) {

                JSONObject rsp = jsonEncryptDecrypt(new JSONObject(value), tenantid, mode);
                // To handle the error
                if (rsp.has(CRYPTO_KEY_NOT_FOUND) || rsp.has(CRYPTO_ERROR)) {
                    return rsp;
                }
                outputMap.put(key, rsp.toString());
            } else if (jsonHandler.validateJSonArray(value)) {
                JSONArray jaobj = new JSONArray(value);
                JSONArray result_jaobj = new JSONArray();
                for (int i = 0; i < jaobj.length(); i++) {
                    JSONObject json_array_var = jsonEncryptDecrypt((JSONObject) jaobj.get(i), tenantid, mode);
                    result_jaobj.put(json_array_var);
                }
                outputMap.put(key, result_jaobj.toString());
            } else {
                String cipherResult = subserviceobj.cipherMethod(mode, tenantid, value);
                //Handling Error
                if (CRYPTO_KEY_NOT_FOUND.equals(cipherResult)) return response_json.put(CRYPTO_KEY_NOT_FOUND, "null");
                else if (CRYPTO_ERROR.equals(cipherResult)) return response_json.put(CRYPTO_ERROR, "");
                outputMap.put(key, cipherResult);
            }
        }
        //Convert encrypted map into JSon Object
        Iterator<String> mapitr = outputMap.keySet().iterator();
        while (mapitr.hasNext()) {
            String key = mapitr.next();
            response_json.put(key, outputMap.get(key));
        }
        return response_json;
    }


    public CryptoResponse encrypt_decrypt(CryptoRequest request, String mode, String type) {
        Map<String, String> encryptedMap = new HashMap<>();

        CryptoResponse response = new CryptoResponse();
        response.setResponseMap(encryptedMap);
        response.setResponseCode(CryptoResponseCode.CRYPTO_ERROR.getValue());

        Map<String, String> plainTextsMap = request.getRequestMap();

        JSONObject reqjson = new JSONObject();
        for (Map.Entry<String, String> entry : plainTextsMap.entrySet())
            reqjson.put(entry.getKey(), entry.getValue());
        JSONObject resp_json;

        if (type.equals("json")) resp_json = jsonEncryptDecrypt(reqjson, request.getTenantId(), mode);
        else resp_json = stringEncryptDecrypt(reqjson, request.getTenantId(), mode);

        if (resp_json.has(CRYPTO_KEY_NOT_FOUND)) {
            response.setResponseCode(CryptoResponseCode.CRYPTO_KEY_NOT_FOUND.getValue());
            return response;
        }
        if (resp_json.has(CRYPTO_ERROR)) {
            response.setResponseCode(CryptoResponseCode.CRYPTO_ERROR.getValue());
            return response;
        }

        //Inserting JSON response into encrypted map form
        Iterator<String> it = resp_json.keySet().iterator();
        while (it.hasNext()) {
            String key = it.next();

            if (jsonHandler.validateNestedJSonObject(resp_json.get(key).toString())) {
                JSONObject temp_obj = new JSONObject(resp_json.get(key).toString());
                encryptedMap.put(key, temp_obj.toString());
            } else encryptedMap.put(key, resp_json.get(key).toString());
        }

        response.setResponseCode(CryptoResponseCode.CRYPTO_SUCCESS.getValue());
        return response;
    }

    public JSONObject stringEncryptDecrypt(JSONObject obj, String tenantid, String mode) {
        //outMap -> EncryptedMap or PlaintextMap
        Map<String, String> outputMap = new HashMap<>();
        JSONObject response_json = new JSONObject();
        Iterator<String> itr = obj.keys();
        while (itr.hasNext()) {
            String key = itr.next();
            String value = obj.get(key).toString();
            String cipherResult = subserviceobj.cipherMethod(mode, tenantid, value);
            //Handling Error
            if (cipherResult.equals(CRYPTO_KEY_NOT_FOUND)) return response_json.put(CRYPTO_KEY_NOT_FOUND, "null");
            else if (cipherResult.equals(CRYPTO_ERROR)) return response_json.put(CRYPTO_ERROR, "");
            outputMap.put(key, cipherResult);
        }
        //Convert encrypted map into JSon Object
        Iterator<String> mapitr = outputMap.keySet().iterator();
        while (mapitr.hasNext()) {
            String key = mapitr.next();
            response_json.put(key, outputMap.get(key));
        }
        return response_json;
    }

    public List<String> getCommonKeysList() {
        return commonKeysList;
    }
}
