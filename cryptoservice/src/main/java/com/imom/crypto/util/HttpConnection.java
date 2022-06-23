package com.imom.crypto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.imom.crypto.config.Config;
import com.imom.crypto.service.jsonHandler;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;


/**
 * Created by devesh on 10/11/17.
 */
public class HttpConnection {

    private HttpConnection() {}

    private static String USER_AGENT = "Mozilla/5.0";
    private static Logger log = Logger.getLogger(HttpConnection.class);

    public static void init(){
        log = Logger.getLogger(HttpConnection.class);
    }

    public static Response hitLBNodes(){
        Response response = null;
        try {
            /*Expecting hostnames from getAllpodIps method in the format: ip:8080
                and appending common pattern to form the complete url*/

            String commonPattern = "/Crypto/V1.1/reload";
            boolean requestStatus;
            String urlString;
            for(String ip : getAllPodsIps()) {
                urlString = "http://"+ip+commonPattern;
                log.info(urlString);
                requestStatus = sendGetRequest(urlString);
                if(!requestStatus){
                    response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("MalformedURLException caught, while checking for "+ urlString +" node").build();
                    return response;
                }
            }
            response = Response.status(Response.Status.OK).entity("all nodes reloaded successfully").build();
            log.info("all nodes reloaded successfully");
        } catch (Exception e) {
            response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Unable to get list of pods").build();
            log.error("error : ", e);
        }
        return response;
    }

    public static boolean sendGetRequest(String urlString){
        boolean requestStatus = true;
        try {
            URL url = new URL(urlString);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();

            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.setRequestProperty("User-Agent",USER_AGENT);

            int responseCode = httpURLConnection.getResponseCode();
            log.info("Sending get request : "+ url);
            log.info("Response code : "+responseCode);

            BufferedReader in = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
            String output;
            StringBuilder response = new StringBuilder();
            while((output = in.readLine())!=null){
                response.append(output);
            }
            in.close();

            log.info(response.toString());

        } catch (IOException e) {
            requestStatus = false;
            log.error("Error: ", e);
        }
        return requestStatus;
    }

    public static HashSet<String> getClientList(String url) {
        HttpURLConnection con = null;
        int responseCode;
        HashSet<String> tenants = new HashSet<>();
        List<Object> clients = new ArrayList<>();
        JSONObject jsonObject = null;

        try {
            URL obj = new URL(url);
            con = (HttpURLConnection)obj.openConnection();
            con.setConnectTimeout(5000);
            con.setRequestMethod("GET");
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Accept", "application/json");
            con.setDoOutput(true);
            con.connect();
            con.getResponseCode();
            responseCode = con.getResponseCode();
            if (responseCode == 200) {
                BufferedReader in;
                String inputLine;
                for(in = new BufferedReader(new InputStreamReader(con.getInputStream())); (inputLine = in.readLine()) != null; jsonObject = jsonHandler.jsonConverter(inputLine)) {
                }

                in.close();
                JSONArray jsonArray = jsonObject.getJSONArray("data");

                jsonArray.forEach(o -> {
                    JSONObject object = (JSONObject) o;
                    clients.add(object.get("refNum").toString());
                    tenants.add(object.get("refNum").toString());
                });



            } else {
                log.error("GET request not worked");
            }
        } catch (Exception e) {
            log.error(e.getMessage() + "key" + url);
        }

        return tenants;
    }

    public static List<String> getAllPodsIps(){
        List<String> podIps = new ArrayList<>();
        try{
            String namespace = Config.getNameSpace();
            String serviceName = Config.getServiceName();
            Path tokenFilePath = Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token");
            String token = Files.readAllLines(tokenFilePath).get(0);
            log.info("Token : " + token);
            String url = "https://kubernetes.default.svc/api/v1/namespaces/"+namespace+"/endpoints/"+serviceName;
            HashMap<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer "+token);
            String response = HttpClientSSL.get(url, headers);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode subsetNode = mapper.readTree(response).get("subsets").get(0);
            ArrayNode arrayNode = (ArrayNode) subsetNode.get("addresses");
            for(int i =0 ;i<arrayNode.size();i++){
                podIps.add(arrayNode.get(i).get("ip").asText()+":"+Config.getServicePort());
            }
        }catch (Exception e){
            log.error("Error while getting AllPod ips : "+e.getMessage());
        }
        log.info("PodIPS : "+podIps);
        return podIps;
    }
}
