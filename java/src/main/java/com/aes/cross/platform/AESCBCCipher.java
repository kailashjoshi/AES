package com.aes.cross.platform;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;


public class AESCBCCipher {
    private byte[] ivSeed = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private final String key = "8!fjVb#GP6V&DX;D";
    private SecureRandom iv;

    public AESCBCCipher() {
        iv = new SecureRandom();
        ivSeed = new byte[16];
        iv.nextBytes(ivSeed);
    }

    public String encrypt(String data) {

        try {
            byte[] keyBytes = key.getBytes("UTF-8");
            byte[] dataBytes = data.getBytes("UTF-8");

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(keyBytes);
            keyBytes = sha.digest();

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            byte[] destination = new byte[ivSeed.length + dataBytes.length];
            System.arraycopy(ivSeed, 0, destination, 0, ivSeed.length);
            System.arraycopy(dataBytes, 0, destination, ivSeed.length, dataBytes.length);
            return new String(Base64.getEncoder().encode(cipher.doFinal(destination)));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String data) {
        try {
            byte[] dataBytes = Base64.getDecoder().decode(data);
            byte[] keyBytes = key.getBytes("UTF-8");

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(keyBytes);
            keyBytes = sha.digest();
            byte[] iv = Arrays.copyOfRange(dataBytes, 0, 16);
            byte[] dec = Arrays.copyOfRange(dataBytes, 16, dataBytes.length);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            return new String(cipher.doFinal(dec));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        AESCBCCipher aes = new AESCBCCipher();
        String enc = aes.encrypt("secretData");
        String dec = aes.decrypt(enc);
        System.out.println(enc);
        System.out.println(dec);

    }
}
