package com.imom.crypto.util;

import com.imom.crypto.config.Config;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static com.imom.crypto.util.Constants.*;


public class KafkaAlertSending {
    private KafkaAlertSending() {}

    private static final CloseableHttpClient httpClient = HttpClients.createDefault();
    private static Logger log = Logger.getLogger(KafkaAlertSending.class);

    public static void sendAlerttoKakfa(String tenandId , String alertType,String subject,String msg) {
        HttpPost request = new HttpPost(Config.getDataSaberUrl());
        Map<String,String> details = KeyGen.getRecipientList(tenandId,alertType);
        if(details.get(CC)==null) details.put(CC,"");
        if(details.get(TO)==null) details.put(TO,"");
        JSONObject reponse = null;
        StringEntity input = null;
        try {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("uuid", UUID.randomUUID().toString());
            jsonObject.put("productName","DEC");
            jsonObject.put("refnum",tenandId);
            jsonObject.put("timestamp",new Date());
            JSONArray alertCommunication = new JSONArray();
            JSONObject emailAlert = new JSONObject();
            emailAlert.put("type","email");
            emailAlert.put("from",Config.getEmailFrom());
            if(details.get(TO).trim().length() > 0) {
                emailAlert.put(TO,details.get(TO).split(","));
            }
            if(details.get(CC).trim().length() > 0) {
            	emailAlert.put(CC,details.get(CC).split(","));
            }
            emailAlert.put("subject",subject);
            emailAlert.put("body",msg);
            alertCommunication.put(emailAlert);
            jsonObject.put("alertCommunication",alertCommunication);
            JSONArray callbackCommunication = new JSONArray();
            JSONObject callBackKafka = new JSONObject();
            callBackKafka.put("type","kafka");
            callBackKafka.put("topic",Config.getKafkaCallbackTopic());
            callBackKafka.put("server",Config.getKafkaBrokers());
            callbackCommunication.put(callBackKafka);
            jsonObject.put("callbackCommunication",callbackCommunication);
            jsonObject.put("pt_dlc_topic",Config.getKafkaTopic());
            input = new StringEntity(jsonObject.toString());
            input.setContentType("application/json");
            request.setEntity(input);

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    reponse = new JSONObject(EntityUtils.toString(entity));
                    jsonObject.put("alertType",alertType);
                    if((int)reponse.get(RESP_STATUS_CODE) == 200)
                        KeyGen.auditAlertHistory(jsonObject , SUCCESS);
                    else
                        KeyGen.auditAlertHistory(jsonObject , FAILED);
                }
            }
        } catch (Exception e) {
           log.error("Getting error while sending kakfa event ", e);
        }
    }
}
