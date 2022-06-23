package com.imom.crypto.cloak;

import com.imom.crypto.config.Config;
import com.imom.crypto.util.RestClient;
import org.apache.http.client.utils.URIBuilder;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

public class CloakServiceManager {

	private final Logger log = Logger.getLogger(CloakServiceManager.class);

	private String login_host;

	private String ph_org_code;
	private String ph_org_type;
	private String product_id;
	private String product_ver;

	protected static Map<String, Map<String, String>> authConfig = new HashMap<>();

	public static Map<String, Map<String, String>> getAuthConfig() {
		return authConfig;
	}

	public CloakServiceManager(String refNum, Map<String, String> headers) {
		
		ph_org_code = headers.get("ph-org-code");
		ph_org_type = headers.get("ph-org-type");

		if (!authConfig.containsKey(refNum+"-"+ph_org_code+"-"+ph_org_type)) {
			log.info("refNum " + refNum + " not found in cahce. Loading.");
			try {
				product_id = Config.getProductId();
				product_ver = Config.getProductVersion();
				login_host = Config.getLoginHost();

				URIBuilder authConfigURL = new URIBuilder(login_host);
				authConfigURL.setPath("/clientauthconfig");
				authConfigURL.addParameter("product_id", product_id);
				authConfigURL.addParameter("product_ver", product_ver);
				authConfigURL.addParameter("ph-org-code", ph_org_code);
				authConfigURL.addParameter("ph-org-type", ph_org_type);

				RestClient restClient = new RestClient();
				JSONObject response = restClient.getAPI(authConfigURL.toString(), null, null);
				parseAuthResponse(response, refNum);
			} catch (URISyntaxException e) {
				log.error("ERORR in CloakServiceManager ctr ",e);
			}
		} else {
			log.info("refNum " + refNum + " found in cahce. Not loading.");
		}
	}

	public void parseAuthResponse(JSONObject response, String refNum) {
		try {
			if (response != null) {
				Map<String, String> tempMap = new HashMap<>();
				JSONObject clientConfig = (JSONObject) ((JSONObject) response.get("data")).get("clientConfig");
				tempMap.put("realm", clientConfig.getString("realm"));
				tempMap.put("resource", clientConfig.getString("resource"));
				tempMap.put("secret", ((JSONObject) clientConfig.get("credentials")).getString("secret"));
				tempMap.put("authServerUrl", clientConfig.getString("auth-server-url"));
				authConfig.put(refNum+"-"+ph_org_code+"-"+ph_org_type, tempMap);
				log.info("Response parsed for " + refNum);
			}
		} catch (Exception e) {
			log.error("ERROR in parse Auth response", e);
		}
	}

	public String getPh_org_code() {
		return ph_org_code;
	}

	public String getPh_org_type() {
		return ph_org_type;
	}

}
