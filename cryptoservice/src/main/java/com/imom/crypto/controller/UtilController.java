package com.imom.crypto.controller;

import com.imom.crypto.config.Config;
import com.imom.crypto.db.DBManager;
import com.imom.crypto.util.*;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Set;

import static com.imom.crypto.util.Constants.RESP_STATUS_CODE;

@Path("/utils")
public class UtilController {

    private static final Logger log = Logger.getLogger(UtilController.class);
    public static final String PROPERTIES_FILE = "/opt/deployment/apache-tomcat/webapps/Crypto/WEB-INF/classes/main/resources/buildInfo.properties";
    MigrationUtils migrationUtils = new MigrationUtils();

    protected static Properties properties;

    public UtilController() {
         properties = FileLoading.loadFile(PROPERTIES_FILE);
    }

    @Path("/getStatus")
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    public Response getSystemStatus() {

        JSONObject respObject = new JSONObject();
        Connection connection = null;
        String mysqlStatus = "red";
        String url = null;
        String username = null;
        String password = null;

        try {
            url = Config.getPassUrl();
            username = Config.getPassUserNamel();
            password = DBManager.getPassword();

            connection = DriverManager.getConnection(url, username, password);
        } catch (Exception ex) {
            respObject.put("mysql", mysqlStatus);
            respObject.put("status", Response.Status.BAD_REQUEST);
            log.error("response for getStatus call : " + respObject.toString());
            log.error("Error : " + ex.getMessage(), ex);
            log.error("Error : Unable to connect to mysql");

            return Response.status(Response.Status.ACCEPTED).entity(respObject.toString()).build();

        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException ignore) {
                    log.error("error : " + ignore.getMessage(), ignore);
                }
            }
        }
        mysqlStatus = "green";
        respObject.put("mysql", mysqlStatus);
        return Response.ok().entity(respObject.toString()).build();
    }

    @Path("/getBuildNumber")
    @GET
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public Response getBuildNumber() {
        HttpConnection.getAllPodsIps();
        JSONObject respObject = new JSONObject();
        String buildNumber = properties.getProperty("build.number");
        respObject.put("buildNumber", buildNumber);
        return Response.ok().entity(respObject.toString()).build();
    }

    @Path("/migrateKeys")
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    public Response migrate() {
        JSONObject resObject = new JSONObject();

        String message = "success";
        resObject.put("statusCode", Response.Status.OK);
        resObject.put("message", message);

        migrationUtils.migrate();
        return Response.ok().entity(resObject.toString()).build();
    }

    @Path("/awsNotify")
    @POST
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response awsNotify(String str) {
        JSONObject jsobj = new JSONObject(str);
        JSONObject resObject = new JSONObject();
        log.info("Request  "+jsobj);
        String keyId = findKeys(jsobj);
        log.info("keyId "+keyId);
        if(keyId != null && DBManager.getTenant(keyId) != null) {
            String refNum = DBManager.getTenant(keyId);
            log.info("refNum "+refNum);
            String eventName = jsobj.getString("eventName");
            String eventTime = jsobj.getString("eventTime");
            String sourceIPAddress = jsobj.getString("sourceIPAddress");
            JSONObject userIdentity = jsobj.getJSONObject("userIdentity");
            String userName = userIdentity.getString("userName");
            String eventSource = jsobj.getString("eventSource");
            String subject = Config.getAccessAlertSubject();
            String body =   Config.getAccessAlertMessage().replace("{eventName}",eventName).replace("{eventTime}",eventTime).replace("{eventSource}",eventSource).replace("{userName}",userName).replace("{sourceIPAddress}",sourceIPAddress);
            KafkaAlertSending.sendAlerttoKakfa(refNum,AlertNames.AWS_Access_Alerts.getValue(), subject, body);
            resObject.put(RESP_STATUS_CODE, Response.Status.OK);
            resObject.put("message", "success");
        } else {
            resObject.put(RESP_STATUS_CODE, Response.Status.OK);
            resObject.put("message", "invalid keyId");
        }
        return Response.ok().entity(resObject.toString()).build();
    }
    public static String findKeys(JSONObject obj) {
        Set<String> keysFromObj = obj.keySet();
        for(String key:keysFromObj) {
            if("keyId".equals(key) || "targetKeyId".equals(key)) {
                return obj.getString(key);
            }
            if(obj.get(key).getClass() == JSONObject.class) {
                return findKeys(obj.getJSONObject(key));
            }
        }
        return null;
    }
}
