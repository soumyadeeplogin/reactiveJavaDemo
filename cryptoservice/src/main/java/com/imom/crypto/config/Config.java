package com.imom.crypto.config;


import com.imom.crypto.util.FileLoading;

import java.util.Properties;


public class Config {

    private Config() {
    }

    public static final String PROPERTIES_FILE = "/opt/deployment/buildproperties/crypto/config.properties";

    protected static Properties properties;

    public static void init() { properties = FileLoading.loadFile(PROPERTIES_FILE); }

    public static String getPadding() {
        return properties.getProperty("crypto.padding");
    }

    public static String getBytesFormat() {
        return properties.getProperty("crypto.bytes.format");
    }

    public static String getKeyPath() {
        return properties.getProperty("crypto.key.path");
    }

    public static int getPassIter() {
        return Integer.parseInt(properties.getProperty("crypto.key.passwd.iter"));
    }

    public static int getKeySize() {
        return Integer.parseInt(properties.getProperty("crypto.key.size"));
    }

    public static String getKeySha() {
        return properties.getProperty("crypto.key.sha");
    }

    public static String getFileExtension() {
        return properties.getProperty("crypto.key.file.extension");
    }

    public static String getKeyFile() {
        return properties.getProperty("crypto.db.key.file");
    }

    public static String getKeyUrl() {
        return properties.getProperty("crypto.db.key.url");
    }

    public static String getKeyUserNamel() {
        return properties.getProperty("crypto.db.key.user.name");
    }

    public static String getKeyPassFile() {
        return properties.getProperty("crypto.db.key.pass.file");
    }

    public static String getPassUrl() {
        return properties.getProperty("crypto.db.pass.url");
    }

    public static String getPassUserNamel() {
        return properties.getProperty("crypto.db.pass.user.name");
    }

    public static String getPassFile() {
        return properties.getProperty("crypto.db.pass.file");
    }

    public static String getLBNodesFile() {
        return properties.getProperty("crypto.lb.nodes.file");
    }

    public static String getCommonKeys() {
        return properties.getProperty("crypto.common.keys");
    }

    public static String getUseSecretsManager() {
        return properties.getProperty("use.secrets.manager");
    }

    public static String getEnv() {
        return properties.getProperty("env");
    }

    public static String getSecretsManagerAWSRegion() {
        return properties.getProperty("secretsmanager.aws.region");
    }

    public static String getSecretNameSuffix() {
        return properties.getProperty("secretname.suffix");
    }

    public static String getKeyManagerUrl() {
        return properties.getProperty("crypto.db.keymanager.url");
    }

    public static String getKeyManagerUserNamel() {
        return properties.getProperty("crypto.db.keymanager.user.name");
    }

    public static String getKeyManagerPassFile() {
        return properties.getProperty("crypto.db.keymanager.pass.file");
    }

    public static String getCMSApi() {
        return properties.getProperty("cmsapi.url");
    }

    public static String getProductEnable() {
        return properties.getProperty("product.enable.flag");
    }

    public static String getTenantCheck() {
        return properties.getProperty("tenant.check");
    }

    public static String getUsername() {
        return properties.getProperty("mail.username");
    }

    public static String getPassword() {
        return properties.getProperty("mail.password");
    }

    public static String getEmailId() {
        return properties.getProperty("mail.emailId");
    }

    public static String getMailSMTPHost() {
        return properties.getProperty("mail.smtp.host");
    }

    public static String getMailSMTPPort() {
        return properties.getProperty("mail.smtp.port");
    }

    public static String getMailSMTPAuth() {
        return properties.getProperty("mail.smtp.auth");
    }

    public static String getMailSMTPEnable() {
        return properties.getProperty("mail.smtp.starttls.enable");
    }

    public static String getWrappingAlgorithm() {
        return properties.getProperty("wrapping.algorithm");
    }

    public static String getValidTo() {
        return properties.getProperty("validto.insec");
    }

    public static String getKmsAccessKey() {
        return properties.getProperty("kms.access.key");
    }

    public static String getKmsSecretKey() {
        return properties.getProperty("kms.secret.key");
    }

    public static String getKmsRegion() {
        return properties.getProperty("kms.region");
    }


    public static long getMinRotationDays() {return Long.parseLong(properties.getProperty("min.rotation.days"));}

    public static String getDataSaberUrl() {return properties.getProperty("data.saber.url");}

    public static String getEmailFrom() {return  properties.getProperty("email.from"); }

    public static String getEmailCC() {return properties.getProperty("email.cc");}

    public static String getSlackChannelId() { return properties.getProperty("slack.channelid");}

    public static String getCreateEmailSubject() {return properties.getProperty("email.create.subject");}

    public static String getCreateEmailMsg() {return properties.getProperty("email.create.msg"); }

    public static String getRotateEmailSubject() {return properties.getProperty("email.rotate.subject");}

    public static String getRotateEmailMsg() {return properties.getProperty("email.rotate.msg"); }

    public static String getKafkaTopic() {return properties.getProperty("kafka.topic");}

	public static String getProductId() { return properties.getProperty("keymanagement.id"); }

	public static String getProductVersion() { return properties.getProperty("keymanagement.version"); }

	public static String getLoginHost() { return properties.getProperty("keymanagement.loginhost"); }

	public static String getUserInfoUrl() {return properties.getProperty("keymanagement.userInfoURL");}

	public static String getAccessAlertSubject () { return  properties.getProperty("access.alert.subject");}

	public static String getAccessAlertMessage() { return  properties.getProperty("access.alert.message");}

	public static String getOwnerName() { return properties.getProperty("owner.name");}

	public static String getOwnerEmailId() {return properties.getProperty("owner.email");}

	public static String getModule() {return properties.getProperty("tag.module");}

	public static String getReason() {return properties.getProperty("tag.reason");}

	public static String getNameSpace() { return properties.getProperty("nameSpace"); }

	public static String getServiceName() { return properties.getProperty("serviceName"); }

	public static String getServicePort() { return properties.getProperty("servicePort"); }

    public static boolean getV2deployment() {return Boolean.parseBoolean(properties.getProperty("v2.deployment"));}

    public static Integer getMaxkeyAge() {return Integer.parseInt(properties.getProperty("max.key.age"));}

    public static Integer getBufferDays() {return Integer.parseInt(properties.getProperty("buffer.days"));}

    public static String getExpirySubject() {return properties.getProperty("email.expiry.suject");}

    public static String getExpiryMessage() {return properties.getProperty("email.expiry.msg");}

    public static String getKafkaBrokers() {return properties.getProperty("kafka.brokers");}

    public static String getKafkaCallbackTopic() {return properties.getProperty("kafka.callback.topic");}

}

