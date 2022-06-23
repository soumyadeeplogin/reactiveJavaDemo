package com.imom.crypto.util;

import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static com.imom.crypto.util.Constants.*;

public class RSAUtils {

    private RSAUtils() {}

    private static final Logger log = Logger.getLogger(RSAUtils.class);

    public static RSAPublicKey X509EncodedKeySpec(final ByteBuffer publicKey) {
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.array());
        try {
            return (RSAPublicKey) KeyFactory.getInstance(RSA).generatePublic(spec);
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            log.error(ERROR + e, e);
            return null;
        }
    }

    public static byte[] encryptRSA(final RSAPublicKey publicKey, final byte[] plaintext) {
        try {
            Cipher oaepFromAlgo = Cipher.getInstance(RSAPADDING);
            String hashFunc = SHA256;
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(hashFunc, MGF1, new MGF1ParameterSpec(hashFunc), PSource.PSpecified.DEFAULT);
            oaepFromAlgo.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
            return oaepFromAlgo.doFinal(plaintext);
        } catch (Exception e) {
            log.error(ERROR + e, e);
            return null;
        }
    }
}

