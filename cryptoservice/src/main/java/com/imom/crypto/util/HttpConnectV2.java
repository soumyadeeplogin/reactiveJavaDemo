package com.imom.crypto.util;

import com.imom.crypto.config.Config;
import org.apache.log4j.Logger;

import javax.ws.rs.core.Response;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpConnectV2 {
    private static String USER_AGENT = "Mozilla/5.0";
    private static Logger log = Logger.getLogger(HttpConnection.class);

    public static void init(){
        log = Logger.getLogger(HttpConnection.class);
    }

    public static Response hitLBNodes(){
        File file = new File(Config.getLBNodesFile());
        Response response = null;
        try (FileInputStream fileInputStream = new FileInputStream(file);
             BufferedReader br = new BufferedReader(new InputStreamReader(fileInputStream));){
            /*Expecting hostnames inside the app_hosts file in the format: dev-dec04.aws.phenom.local:6552
                and appending common pattern to form the complete url*/

            String line = null;
            String commonPattern = "/Crypto/V1.1/reload";
            boolean requestStatus;
            String urlString;
            while ((line = br.readLine()) != null) {
                urlString = "http://"+line+commonPattern;
                log.info(urlString);
                requestStatus = sendGetRequest(urlString);
                if(!requestStatus){
                    response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("MalformedURLException caught, check for "+ urlString +" node in app_hosts.txt file").build();
                    return response;
                }
            }
            response = Response.status(Response.Status.OK).entity("all nodes reloaded successfully").build();
            log.info("all nodes reloaded successfully");
        } catch (Exception e) {
            response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("app_hosts.txt file could not be opened/not found").build();
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
}
