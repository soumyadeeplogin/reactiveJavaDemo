package com.imom.crypto.util;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

public class FileLoading {

    private static final Logger log = Logger.getLogger(FileLoading.class);

    private FileLoading() {}

    public static Properties loadFile(String path) {
       try {
           Properties properties = new Properties();
           File file = new File(path);
           FileInputStream fileInput;
           try {
               fileInput = new FileInputStream(file);
               properties.load(fileInput);
               fileInput.close();
           } catch (Exception e) {
               log.error(e.getMessage(), e);
           }
           return properties;
       } catch (Exception ex) {
           log.error("ERROR "+ex.getMessage(),ex);
       }
       return null;
    }
}
