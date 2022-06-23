package com.imom.crypto.service;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Iterator;

public class jsonHandler {

    private jsonHandler() {
    }

    public static boolean validateNestedJSonObject(String str) {
        try {
            new JSONObject(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean validateJSonArray(String str) {
        try {
            new JSONArray(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    public static JSONObject jsonConverter(String jsonstr) {

        JSONObject json_obj = new JSONObject(jsonstr);
        JSONObject ret = new JSONObject();

        Iterator<String> itr = json_obj.keySet().iterator();
        while (itr.hasNext()) {
            String key = itr.next();
            String value = json_obj.get(key).toString();

            if (validateNestedJSonObject(value)) {
                JSONObject obj = jsonConverter(value);
                ret.put(key, obj);
            } else if (validateJSonArray(value)) {
                JSONArray jaobj = new JSONArray(value);
                JSONArray result_jaobj = new JSONArray();
                for (int i = 0; i < jaobj.length(); i++) {
                    JSONObject json_array_var = jsonConverter(jaobj.get(i).toString());
                    result_jaobj.put(json_array_var);
                }
                ret.put(key, result_jaobj);
            } else ret.put(key, value);
        }
        return ret;
    }
}
