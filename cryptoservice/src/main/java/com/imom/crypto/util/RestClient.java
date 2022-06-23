package com.imom.crypto.util;


import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static com.imom.crypto.util.Constants.RESP_STATUS_CODE;


public class RestClient {
    private static final Logger log = Logger.getLogger(RestClient.class);
    private static final RestClient REST_CLIENT = new RestClient();

    public static RestClient getRestClinet() {
        return REST_CLIENT;
    }

    public JSONObject postAPI(String url, List<NameValuePair>  payload, Header[] headers) {
        CloseableHttpClient client = HttpClients.createDefault();
        JSONObject response = null;
        CloseableHttpResponse _response = null;
        try {
            HttpPost postReq = new HttpPost(url);
            postReq.setHeaders(headers);
          
            postReq.setEntity((HttpEntity) new UrlEncodedFormEntity(payload));
            _response = client.execute(postReq);
            String resp = IOUtils.toString(_response.getEntity().getContent(), StandardCharsets.UTF_8);
            response = new JSONObject(resp);
            log.debug(response);
            if(!response.has(RESP_STATUS_CODE)) {
                StatusLine statusLine = _response.getStatusLine();
                response.put(RESP_STATUS_CODE, statusLine.getStatusCode());
            }
        }catch (Exception e) {
            log.error(e.getMessage(), e);
        }finally {
            try {
                if(_response != null)
                    _response.close();
                if(client != null)
                    client.close();
            }catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
        return response;
    }
    
    public JSONObject getAPI(String url, String  payload, Header[] headers) {
        CloseableHttpClient client = HttpClients.createDefault();
        JSONObject response = null;
        CloseableHttpResponse _response = null;
        try {
            HttpGet getReq = new HttpGet(url);
            getReq.setHeaders(headers);
//            HttpEntity entity = new StringEntity(payload.toString());
//            getReq.setEntity(entity);
            _response = client.execute(getReq);
            String resp = IOUtils.toString(_response.getEntity().getContent(), StandardCharsets.UTF_8);
            response = new JSONObject(resp);
            log.debug(response);
            if(!response.has(RESP_STATUS_CODE)) {
                StatusLine statusLine = _response.getStatusLine();
                response.put(RESP_STATUS_CODE, statusLine.getStatusCode());
            }
        }catch (Exception e) {
            log.error(e.getMessage(), e);
        }finally {
            try {
                if(_response != null)
                    _response.close();
                if(client != null)
                    client.close();
            }catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
        return response;
    }

}
