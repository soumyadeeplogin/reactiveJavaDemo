package com.phenom.etg.utils;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import static com.phenom.etg.utils.Constants.*;

@Component
public class TokenIntrospection {

    private static final Logger log = Logger.getLogger(TokenIntrospection.class);

    public JSONObject getPayLoad(String authorization) {
        JSONObject payLoad = new JSONObject();
        String token = authorization.replaceAll("Bearer ", "");
        log.debug(token);
        try {
            String[] chunks = token.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();

            String header = new String(decoder.decode(chunks[0]));
            String payload = new String(decoder.decode(chunks[1]));

            log.debug(header);
            log.debug(payload);
            payLoad = new JSONObject(payload);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return payLoad;
    }

    public String getUserId(String authorization) {
        String userId = "UserId not found";
        try {
            JSONObject payloadJson = getPayLoad(authorization);
            if (payloadJson.has(USER_DETAILS)) {
                log.debug("userId :: " + payloadJson.getJSONObject(USER_DETAILS).getString(USER_ID_TOKEN));
                return payloadJson.getJSONObject(USER_DETAILS).getString(USER_ID_TOKEN);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return userId;
    }

    public String getEmail(String authorization) {
        String email = "email not found";
        try {
            JSONObject payloadJson = getPayLoad(authorization);
            if (payloadJson.has(USER_DETAILS)) {
                log.debug("email :: " + payloadJson.getJSONObject(USER_DETAILS).getString(EMAIL));
                return payloadJson.getJSONObject(USER_DETAILS).getString(EMAIL);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return email;
    }

    public String getUserName(String authorization) {
        String userName = "userName not found";
        try {
            JSONObject payloadJson = getPayLoad(authorization);
            if (payloadJson.has(USER_NAME)) {
                log.debug("userName :: " + payloadJson.getString(USER_NAME));
                return payloadJson.getString(USER_NAME);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return userName;
    }

    public List<String> getEntitlement(String authorization) {
        List<String> entitlements = new ArrayList<>();
        try {
            JSONObject payloadJson = getPayLoad(authorization);
            if (payloadJson.has(ENTITLEMENTS)) {
                JSONArray entitlementsA = payloadJson.getJSONArray(ENTITLEMENTS);
                for (int i = 0; i < entitlementsA.length(); i++)
                    entitlements.add(entitlementsA.getString(i));
                log.debug("Entitlements :: " + entitlements);
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return entitlements;
    }

    public boolean isResourceAvailable(String authorization) {
        try {
            JSONObject payloadJson = getPayLoad(authorization);
            if (payloadJson.has(RESOURCE_ACCESS)) {
                JSONObject resources = payloadJson.getJSONObject(RESOURCE_ACCESS);
                return resources.has(ECF_UI) || resources.has(ECF_API) || checkEntitlementList(authorization);
            } else
                return false;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return false;
        }
    }

    private boolean checkEntitlementList(String authorization) {
        Iterator<String> itr = getEntitlement(authorization).iterator();
        JSONObject payloadJson = getPayLoad(authorization);
        while(itr.hasNext())
        {
            String next = itr.next().toLowerCase()+"-";
            if (payloadJson.has(RESOURCE_ACCESS)) {
                JSONObject resources = payloadJson.getJSONObject(RESOURCE_ACCESS);
                if(resources.has(next+ECF_API) || resources.has(next+ECF_UI))
                    return true;
            }
        }
        return false;
    }

    public boolean isClientRequestValid(String authorization, String refNum) {
        return getEntitlement(authorization).contains(refNum) || getEntitlement(authorization).contains("ALL");
    }
}
