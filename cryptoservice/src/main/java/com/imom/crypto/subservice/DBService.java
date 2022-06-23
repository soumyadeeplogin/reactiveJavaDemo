package com.imom.crypto.subservice;

import com.imom.crypto.api.CryptoResponse;
import com.imom.crypto.bean.PassData;
import com.imom.crypto.config.Config;
import com.imom.crypto.manager.KeyManager;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.imom.crypto.util.Constants.*;

public class DBService implements SubService {

    private static final Logger log = Logger.getLogger(DBService.class);
    private static final String ERROR = "Error: ";

    /**
     * This method create cipher with the key
     *
     * @param mode,    mode encryption/decryption
     * @param keyBytes
     * @return Cipher
     * @see Cipher
     */
    private Cipher getCipher(int mode, byte[] keyBytes) {

        try {

            SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance(Config.getPadding());
            cipher.init(mode, secret);

            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            log.error(ERROR, e);
        }

        return null;
    }


    public byte[] generateKey(PassData passData) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(Config.getKeySha());
            PBEKeySpec spec = new PBEKeySpec(new String(passData.getPasswd()).toCharArray(), passData.getSalt(), Config.getPassIter(), Config.getKeySize());
            SecretKey secretKey = factory.generateSecret(spec);
            return secretKey.getEncoded();
        } catch (Exception e) {
            log.error(ERROR + e);
            log.error(ERROR + e.getMessage(), e);
        }

        return null;
    }

    /**
     * This method encrypts data with AES 256
     *
     * @param tenantid , CryptoRequest with map of key value pairs of data for which
     *                 the encryption needs to be done and tenantId
     * @return CryptoResponse
     * @see CryptoResponse
     */
    public byte[] getkeybytes(String tenantid) {
        byte[] keyBytes = null;
        try {
            keyBytes = KeyManager.getKey(tenantid);
        } catch (Exception e1) {
            log.error(ERROR + e1);
        }
        return keyBytes;
    }


    public String cipherMethod(String mode, String tenantId, String value) {
        byte[] keyBytes = getkeybytes(tenantId);
        if (keyBytes == null) {
            return CRYPTO_KEY_NOT_FOUND;
        }
        try {
            if (ENCRYPT.equals(mode)) {
                Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, keyBytes);
                String encryptedString = null;
                if (cipher != null) {
                    byte[] encryptedTextBytes = cipher.doFinal(value.getBytes(Config.getBytesFormat()));
                    encryptedString = new Base64().encodeAsString(encryptedTextBytes);
                }
                return encryptedString;
            } else if (DECRYPT.equals(mode)) {
                Cipher cipher = getCipher(Cipher.DECRYPT_MODE, keyBytes);
                byte[] encryptedTextBytes = null;
                byte[] decryptedTextBytes = null;
                if (cipher != null) {
                    encryptedTextBytes = Base64.decodeBase64(value);
                    decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
                }
                return new String(decryptedTextBytes);
            } else {
                return null;
            }
        } catch (Exception e) {
            log.error(ERROR, e);
            return CRYPTO_ERROR;
        }

    }
}

