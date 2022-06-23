package com.imom.crypto.controller;

import com.amazonaws.services.kms.model.OriginType;
import com.imom.crypto.cloak.GetUserInfo;
import com.imom.crypto.config.Config;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.manager.KMSKeys;
import com.imom.crypto.util.*;
import com.sun.jersey.api.NotFoundException;
import com.sun.jersey.core.header.FormDataContentDisposition;
import com.sun.jersey.multipart.FormDataParam;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;
import java.io.*;
import java.util.*;

import static com.imom.crypto.util.Constants.*;

@Path("/keymanagement-ui")
public class KeyManangementController {
    private final Logger log = Logger.getLogger(KeyManangementController.class);

    private final Object lock = new Object();

    @Path("/rotatebyok")
    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces({MediaType.APPLICATION_JSON})
    public Response byok(@Context HttpServletRequest req,@FormDataParam("keyfile") InputStream is,
                         @FormDataParam("keyfile") FormDataContentDisposition fileDetail,
                         @FormDataParam("tenantId") String tenantId,
                         @FormDataParam("user") String user,
                         @FormDataParam("source") String source) throws IOException {

        log.info("tenantId "+tenantId);
        log.info("user "+user);
        log.info("source "+source);
        log.info("fileDetail "+fileDetail.getFileName());

        byte[] plainTextKey = org.apache.commons.io.IOUtils.toByteArray(is);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(TENANT_ID,tenantId);
        jsonObject.put("user",user);
        jsonObject.put(SOURCE,source);
        jsonObject.put("plainTextKey", Base64.getEncoder().encodeToString(plainTextKey));

        rotateCmk(req,jsonObject.toString());
        log.info("PRINTING FILE\n\n"+ Base64.getEncoder().encodeToString(plainTextKey)+"\n\n\n END OF FILE");

        return Response.status(Response.Status.OK).build();

    }

    @Path("/rotatecmk")
    @POST
    @Produces({MediaType.APPLICATION_JSON})
    public Response rotateCmk(@Context HttpServletRequest request, String str) {
    	
    	List<String> roles = Arrays.asList("admin","super_admin");
    	if(!getAuthentication(request, roles))
    		return Response.status(Response.Status.UNAUTHORIZED).build(); 
    	
        Response response = null;
        JSONObject body = new JSONObject();
        synchronized (lock) {
            DBManager.reloadMaps();
            JSONObject jsobj = new JSONObject(str);

            if (!jsobj.has(TENANT_ID) || "".equals(jsobj.getString(TENANT_ID))) {
                log.warn("tenantId null");
                return Response.status(Response.Status.BAD_REQUEST).entity("tenantId null").build();
            }

            if (TRUE_VALUE.equals(Config.getTenantCheck())) {
                HashSet<String> tenants = HttpConnection.getClientList(Config.getCMSApi());
                if (!tenants.contains(jsobj.getString(TENANT_ID))) {
                    log.warn("Incorrect tenantId");
                    return Response.status(Response.Status.BAD_REQUEST).entity("Incorrect tenantId").build();
                }
            }

            if(!jsobj.has("user")  || "".equals(jsobj.getString("user"))) {
                log.warn("user is null");
                return Response.status(Response.Status.BAD_REQUEST).entity("user is null").build();
            }

            KMSKeys kmsKeys = new KMSKeys();

            if (jsobj.has(SOURCE))
                kmsKeys.setSources(jsobj.getString(SOURCE));

            //if source is not present consider internal
            if (kmsKeys.getSources() == null) {
                log.info("Source is null / source is not present for "+jsobj.getString(TENANT_ID));
                kmsKeys.setSources(OriginType.AWS_KMS.toString());
            }

            kmsKeys.setPlaintextKey(null);

            if(kmsKeys.getSources() != null && jsobj.has("plainTextKey")) {
                kmsKeys.setPlaintextKey(Base64.getDecoder().decode(jsobj.getString("plainTextKey")));
            }

            kmsKeys.setTenantId(jsobj.getString(TENANT_ID));
            kmsKeys.setUser(jsobj.getString("user"));
            kmsKeys.setIpAddress(request.getRemoteAddr());

            KMSKeys resp = KeyGen.rotateCmk(kmsKeys);

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
                log.info("successfully rotated "+kmsKeys.getTenantId());
                return Response.status(Response.Status.OK).entity("successfully rotated "+kmsKeys.getTenantId()).build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Key is not rotated successfully "+kmsKeys.getTenantId()).build();
        }
    }

    @Path("/getKeysInfo")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getClientInfo(@Context HttpServletRequest request, String str) {
        try {

            List<String> roles = Arrays.asList("admin","super_admin","user");
        	if(!getAuthentication(request, roles))
        		return Response.status(Response.Status.UNAUTHORIZED).build();

            JSONObject body = new JSONObject();
            JSONObject jsobj = new JSONObject(str);
            String tenantId = jsobj.getString(TENANT_ID);
            List<KMSKeys> activekeys = new ArrayList<>();
            Map<String,Integer> timesInfo = KeyGen.getKeyAgeConfig(tenantId);
            if(timesInfo == null)
                 timesInfo = new HashMap<>();
            if(timesInfo.get(tenantId) == null)
                timesInfo.put(tenantId,Config.getMaxkeyAge());
            timesInfo.put("buffer_time",Config.getBufferDays());
            activekeys.add(DBManager.getCmks(tenantId));
            body.put("activeKey",activekeys);
            body.put("history", DBManager.getKeyInfo(tenantId));
            body.put("timeInfo",timesInfo);
            return Response.status(Response.Status.OK).entity(body.toString()).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @Path("/addAlert")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response addAtert(@Context HttpServletRequest request,String str) {
        JSONObject jsobj = new JSONObject(str);
        synchronized (lock) {
            String keyPassword = DBManager.getKeyManagerPassword();
            jsobj.put("ipAddress",request.getRemoteAddr());
            List<Map<String, Object>> results = KeyGen.getAlertConfig(jsobj.getString("tenantId"),Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), keyPassword);
            for (Map<String,Object> result:results) {
                if(result.get("alertType").equals(jsobj.getString("alertType"))) {
                    return Response.status(Response.Status.CONFLICT).build();
                }
            }
            KeyGen.addAlertConfig(jsobj,keyPassword);
        }
        return Response.status(Response.Status.OK).build();
    }

    @Path("/updateAlert")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response updateAtert(@Context HttpServletRequest request,String str) {
       try {
           JSONObject jsobj = new JSONObject(str);
           JSONObject body = new JSONObject();
           synchronized (lock) {
               String keyPassword = DBManager.getKeyManagerPassword();
               jsobj.put("ipAddress",request.getRemoteAddr());
               KeyGen.updateAlertConfig(jsobj, keyPassword);
               return Response.status(Response.Status.OK).entity("Updated successfully").build();
           }
       } catch (Exception exception) {
           return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
       }
    }

    @Path("/getUserInfo")
    @GET
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getUserInfo(@Context HttpServletRequest request) {
        JSONObject body = new JSONObject();
        JSONArray jsonArray = getRoles(request);
        if(jsonArray != null)
          body.put("roles",jsonArray);
        else body.put("roles",new JSONObject[0]);
        return Response.status(Response.Status.OK).entity(body.toString()).build();
    }



    @Path("/getAlertConfig")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAlertConfig(String str) {
       try {
           JSONObject jsobj = new JSONObject(str);
           JSONObject body = new JSONObject();
           String keyPassword = DBManager.getKeyManagerPassword();
           body.put("alerts", KeyGen.getAlertConfig(jsobj.getString("tenantId"),Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), keyPassword));
           return Response.status(Response.Status.OK).entity(body.toString()).build();
       } catch (Exception e) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build(); }

    }

    @Path("/getAlertHistory")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAlertHistory(String str) {
        try {
            JSONObject jsobj = new JSONObject(str);
            JSONObject body = new JSONObject();
            String keyPassword = DBManager.getKeyManagerPassword();
            body.put("alertsHistory", KeyGen.getAlertHistory(jsobj.getString("tenantId"),Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), keyPassword));
            return Response.status(Response.Status.OK).entity(body.toString()).build();
        } catch (Exception e) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build(); }

    }

    @Path("/getActivityLogs")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getActivityLogs(String str) {
        try {
            JSONObject jsobj = new JSONObject(str);
            JSONObject body = new JSONObject();
            String keyPassword = DBManager.getKeyManagerPassword();
            body.put("ActivityLogs", KeyGen.getActivityLogs(jsobj.getString("tenantId"), keyPassword,false));
            return Response.status(Response.Status.OK).entity(body.toString()).build();
        } catch (Exception e) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build(); }

    }

    private JSONArray getRoles (HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        headers.put("ph-org-code", request.getHeader("ph-org-code"));
        headers.put("ph-org-type", request.getHeader("ph-org-type"));
        headers.put("token", request.getHeader("token"));
        String refNum = headers.get("ph-org-code");
        JSONObject response = new GetUserInfo(refNum, headers).getUserInfo();
        if(response.has("roles"))
           return response.getJSONArray("roles");
        else return null;
    }

    public boolean getAuthentication(HttpServletRequest request,List<String> roles)
    {
    		JSONArray jarray = getRoles(request);
    		if(jarray != null) {

                for (int i = 0; i < jarray.length(); i++) {
                    String responseRole = (String) jarray.get(i);
                    for (String role : roles) {
                        if (responseRole.equals(role))
                            return true;
                    }
                }
            }
    	return false;
    }


    @Path("/getExpiryDetails")
    @POST
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response getExpiryDetails(String str) {
        JSONObject jsobj = new JSONObject(str);
        Response response = null;
        DBManager.reloadMaps();
        boolean toRoloadall = false;
        List<Map<String ,Object>> expiryDetailsMap = new ArrayList<>();

        if(!jsobj.has("sendAlert"))
            return Response.status(Response.Status.BAD_REQUEST).entity("sendAlert not present").build();

        boolean sendAlert = jsobj.getBoolean("sendAlert");

        int buffer_days = Config.getBufferDays();
        if(jsobj.has("days"))
            buffer_days = jsobj.getInt("days");

        Map<String, KMSKeys> cmks = DBManager.getCmks();
        
        int max_key_age_def = Config.getMaxkeyAge();

        for (Map.Entry<String,KMSKeys> cmkEntry :cmks.entrySet()) {
            Map<String,Object> expiryDetails = new HashMap<>();
            String tenantId = cmkEntry.getKey();

            expiryDetails.put("tenantId",tenantId);
            long keyAge = ((System.currentTimeMillis()-cmkEntry.getValue().getStartDate().getTime())/(1000*60*60*24));
            expiryDetails.put("keyAge",keyAge);
            Map<String, Integer> keyAgeConfig = KeyGen.getKeyAgeConfig(tenantId);

            Integer max_key_age_conf;
            if((max_key_age_conf = keyAgeConfig.get(cmkEntry.getKey())) == null ) {
                max_key_age_conf = max_key_age_def;
            }

            Date expiryDate = new Date(cmkEntry.getValue().getStartDate().getTime() + (max_key_age_conf*1000*60*60*24l));
            expiryDetails.put("expiryDate",expiryDate);
            long expiryDays = max_key_age_conf - keyAge;
            if(sendAlert) {
                Map<String,String> expiryAlertDetails = KeyGen.getRecipientList(tenantId, AlertNames.AWS_Expiry_Alerts.getValue());
                if(expiryAlertDetails != null && expiryAlertDetails.size() > 0 && expiryDays <= Long.parseLong(expiryAlertDetails.get("days"))) {
                    String expiryMsg = Config.getExpiryMessage().replace("{indays}",String.valueOf(expiryDays)).replace("{date}",expiryDate.toString());
                    KafkaAlertSending.sendAlerttoKakfa(tenantId,AlertNames.AWS_Expiry_Alerts.getValue(),Config.getExpirySubject(),expiryMsg);
                }
            }
            if(expiryDays-buffer_days <= 0) {
                KMSKeys kmsKeys = new KMSKeys();
                kmsKeys.setTenantId(tenantId);
                kmsKeys.setUser("System");
                kmsKeys.setIpAddress("System");
                KMSKeys resp = KeyGen.rotateCmk(kmsKeys);
                if(resp != null) {
                    log.info("successfully rotated "+tenantId);
                    toRoloadall = true;
                } else log.info("Not Successfully Rotated for "+tenantId);
            }

            expiryDetails.put("source",cmkEntry.getValue().getSources());

            expiryDetailsMap.add(expiryDetails);
        }

        if(toRoloadall) {
            log.info("starting hitLBNodes method");
            if(Config.getV2deployment())
                response = HttpConnectV2.hitLBNodes();
            else response = HttpConnection.hitLBNodes();
            log.info("ending hitLBNodes method");
        }

        JSONObject resObject = new JSONObject();
        String message = "success";
        resObject.put("statusCode", Response.Status.OK);
        resObject.put("message", message);
        resObject.put("expiryDetails",expiryDetailsMap);
        return Response.ok().entity(resObject.toString()).build();
    }


    @Path("/getActivitiesLogsFile/{tenantId}")
    @GET
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_OCTET_STREAM})
    public StreamingOutput getActivitiesLogsFile(@PathParam("tenantId") final String tenantId) {

        XlseUtility.createExcel(tenantId,DBManager.getKeyManagerPassword());
        return new StreamingOutput() {
            @Override
            public void write(OutputStream output) throws IOException, WebApplicationException {
                try (InputStream in = new FileInputStream(new File("ActivitiesLogs.xlsx"))) {
                     output.write(IOUtils.readBytesFromStream(in));
                } catch (final FileNotFoundException ex) {
                    throw new NotFoundException("Document does not exist");
                }
            }
        };
    }

    @Path("/deleteAlertConfig")
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_OCTET_STREAM})
    public Response deleteAlertConfig(@Context HttpServletRequest request,String str) {
        try {
            List<String> roles = Arrays.asList("admin","super_admin");
            if(!getAuthentication(request, roles))
                return Response.status(Response.Status.UNAUTHORIZED).build();

            JSONObject jsobj = new JSONObject(str);
            JSONObject body = new JSONObject();

            if(jsobj.getString("tenantId").trim().isEmpty())
                return Response.status(Response.Status.BAD_REQUEST).entity("tenantId is empty").build();

            String keyPassword = DBManager.getKeyManagerPassword();
            jsobj.put("ipAddress",request.getRemoteAddr());
            KeyGen.deleteAlertConfig(jsobj, keyPassword);
            body.put("alerts", KeyGen.getAlertConfig(jsobj.getString("tenantId"),Config.getKeyManagerUrl(), Config.getKeyManagerUserNamel(), keyPassword));
            return Response.status(Response.Status.OK).entity(body.toString()).build();
        } catch (Exception exception) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}
