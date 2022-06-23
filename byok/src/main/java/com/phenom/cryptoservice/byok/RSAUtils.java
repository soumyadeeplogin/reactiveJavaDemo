package com.phenom.cryptoservice.byok;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {
    public static RSAPublicKey decodeX509PublicKey(final ByteBuffer publicKey) {
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.array());
        try {
            final RSAPublicKey pk = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
            return pk;
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encryptRSA(final RSAPublicKey publicKey, final byte[] plaintext) {
        try {
            /*
             * This must match what KMS expects which was chosen in the call to GetParametersForImport
             */
            Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            String hashFunc = "SHA-256";
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(hashFunc, "MGF1", new MGF1ParameterSpec(hashFunc), PSource.PSpecified.DEFAULT);
            oaepFromAlgo.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
            byte[] cipherDer = oaepFromAlgo.doFinal(plaintext);
            /*final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            final byte[] ciphertext = cipher.doFinal(plaintext);*/
            return cipherDer;
        } catch (final InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
}