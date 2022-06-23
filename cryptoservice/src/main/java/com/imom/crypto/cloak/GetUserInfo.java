package com.imom.crypto.cloak;

import com.imom.crypto.config.Config;
import com.imom.crypto.util.RestClient;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.util.Map;

import static com.imom.crypto.util.Constants.APPLICATION_JSON;
import static com.imom.crypto.util.Constants.CONTENT_TYPE;

public class GetUserInfo extends CloakServiceManager{
	
	private final Logger log = Logger.getLogger(GetUserInfo.class);
	
	String refNum = "";
	String token = "";

	public GetUserInfo(String refNum, Map<String, String> headers) {
		super(refNum, headers);
		this.token = headers.get("token");
		this.refNum = refNum;
	}
	
	public JSONObject getUserInfo() {
		try {
			String s_URL = Config.getUserInfoUrl();
			s_URL = s_URL.replace("{host}", ((Map<String, String>)authConfig.get(refNum+"-"+getPh_org_code()+"-"+getPh_org_type())).get("authServerUrl").toString());
			s_URL = s_URL.replace("{realm}", ((Map<String, String>)authConfig.get(refNum+"-"+getPh_org_code()+"-"+getPh_org_type())).get("realm").toString());
			Header[] headers = {new BasicHeader(CONTENT_TYPE, APPLICATION_JSON),
					new BasicHeader("Authorization", "Bearer "+token)};
			RestClient restClient = new RestClient();
			JSONObject response = restClient.getAPI(s_URL, null, headers);
			return parseResponse(response);
		} catch (Exception e) {
			log.error("ERROR in get user info ",e);
		} 
		return new JSONObject("{\"error\":\"failed\"}");
	}
	
	public JSONObject parseResponse(JSONObject response)
	{
		if(response.has("error")) return response;
		JSONObject returnResponse = new JSONObject();
		returnResponse.put("entitlements", response.getJSONArray("entitlements"));
		String resources_key = authConfig.get(refNum+"-"+getPh_org_code()+"-"+getPh_org_type()).get("resource");
		returnResponse.put("roles", response.getJSONObject("resources").getJSONObject(resources_key).getJSONArray("roles"));
		return returnResponse;
	}
}
