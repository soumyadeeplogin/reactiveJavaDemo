package com.imom.crypto.util;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class HttpClientSSL {
    private static Logger log = Logger.getLogger(HttpClientSSL.class);

    private HttpClientSSL() {}

    public static CloseableHttpClient getCloseableHttpClient() {
        CloseableHttpClient httpClient = null;
        try {
            httpClient = HttpClients.custom().
                    setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).
                    setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, (arg0, arg1) -> true).build()).build();
        } catch (KeyManagementException e) {
            log.error("KeyManagementException in creating http client instance", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithmException in creating http client instance", e);
        } catch (KeyStoreException e) {
            log.error("KeyStoreException in creating http client instance", e);
        }
        return httpClient;
    }

    public static String get(String url, HashMap<String, String> headers) throws IOException {
        try {
            HttpGet httpGet = new HttpGet(url);
            if (headers != null && headers.size() > 0) {
                for (Map.Entry<String, String> entrySet : headers.entrySet()) {
                    httpGet.addHeader(entrySet.getKey(), entrySet.getValue());
                }
            }
            CloseableHttpClient closeableHttpClient = getCloseableHttpClient();
            CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(httpGet);
            return EntityUtils.toString(closeableHttpResponse.getEntity());
        } catch (Exception exception) {
            log.error("ERROR :"+exception.getMessage(),exception);
        }
        return null;
    }
}
