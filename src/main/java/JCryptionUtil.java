package com.todaytech.gfmis.charge.util.rsa;

import com.todaytech.util.string.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class JCryptionUtil {
    public static final Provider provider = new BouncyCastleProvider();

    public JCryptionUtil() throws Exception {
        Security.addProvider(provider);
    }

    public static KeyPair generateKeypair(int keyLength) throws Exception {
        try {
            KeyPairGenerator kpg;
            try {
                kpg = KeyPairGenerator.getInstance("RSA");
            } catch (Exception var3) {
                kpg = KeyPairGenerator.getInstance("RSA", provider);
            }

            kpg.initialize(keyLength);
            KeyPair keyPair = kpg.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException var4) {
            throw new RuntimeException("RSA algorithm not supported", var4);
        } catch (Exception var5) {
            throw new Exception("other exceptions", var5);
        }
    }

    public static String keyPairPublicKeyToString(KeyPair keypair, int keyLength) {
        String e = getPublicKeyExponent(keypair);
        String n = getPublicKeyModulus(keypair);
        String md = String.valueOf(getMaxDigits(keyLength));
        StringBuffer out = new StringBuffer();
        out.append("{\"e\":\"");
        out.append(e);
        out.append("\",\"n\":\"");
        out.append(n);
        out.append("\",\"maxdigits\":\"");
        out.append(md);
        out.append("\"}");
        return out.toString();
    }

    public static String keyPairPrivateKeyToString(KeyPair keypair, int keyLength) {
        String e = getPrivateKeyExponent(keypair);
        String n = getPrivateKeyModulus(keypair);
        String md = String.valueOf(getMaxDigits(keyLength));
        StringBuffer out = new StringBuffer();
        out.append("{\"e\":\"");
        out.append(e);
        out.append("\",\"n\":\"");
        out.append(n);
        out.append("\",\"maxdigits\":\"");
        out.append(md);
        out.append("\"}");
        return out.toString();
    }

    public static String decrypt(String encrypted, KeyPair keys) throws Exception {
        Cipher dec;
        try {
            try {
                dec = Cipher.getInstance("RSA/NONE/NoPadding");
            } catch (Exception var8) {
                dec = Cipher.getInstance("RSA/NONE/NoPadding", provider);
            }

            dec.init(Cipher.DECRYPT_MODE, keys.getPrivate());
        } catch (GeneralSecurityException var9) {
            throw new RuntimeException("RSA algorithm not supported", var9);
        }

        String[] blocks = encrypted.split("\\s");
        StringBuffer result = new StringBuffer();

        try {
            for (int i = blocks.length - 1; i >= 0; --i) {
                byte[] data = hexStringToByteArray(blocks[i]);
                byte[] decryptedBlock = dec.doFinal(data);
                result.append(new String(decryptedBlock));
            }
        } catch (GeneralSecurityException var10) {
            throw new RuntimeException("Decrypt error", var10);
        }

        return result.reverse().toString().substring(2);
    }

    public static Map parse(String url, String encoding) {
        try {
            String urlToParse = URLDecoder.decode(url, encoding);
            String[] params = urlToParse.split("&");
            Map parsed = new HashMap();

            for (int i = 0; i < params.length; ++i) {
                String[] p = params[i].split("=");
                String name = p[0];
                String value = p.length == 2 ? p[1] : null;
                parsed.put(name, value);
            }

            return parsed;
        } catch (UnsupportedEncodingException var9) {
            throw new RuntimeException("Unknown encoding.", var9);
        }
    }

    public static String getPublicKeyModulus(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return publicKey.getModulus().toString(16);
    }

    public static String getPublicKeyExponent(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return publicKey.getPublicExponent().toString(16);
    }

    public static String getPrivateKeyModulus(KeyPair keyPair) {
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return privateKey.getModulus().toString(16);
    }

    public static String getPrivateKeyExponent(KeyPair keyPair) {
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return privateKey.getPrivateExponent().toString(16);
    }

    public static int getMaxDigits(int keyLength) {
        return keyLength * 2 / 16 + 3;
    }

    /**
     * 16进制字符串转字节码
     *
     * @param s 16进制字符串
     * @return 字节数组
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuffer result = new StringBuffer();

        for (int i = 0; i < bytes.length; ++i) {
            result.append(Integer.toString((bytes[i] & 255) + 256, 16).substring(1));
        }

        return result.toString();
    }

    /**
     * 16进制字符串转字节码
     *
     * @param s 16进制字符串
     * @return 字节数组
     */
    public static byte[] hexStringToByteArray(String data) {
        int k = 0;
        byte[] results = new byte[data.length() / 2];

        for (int i = 0; i < data.length(); ++k) {
            results[k] = (byte) (Character.digit(data.charAt(i++), 16) << 4);
            results[k] += (byte) Character.digit(data.charAt(i++), 16);
        }

        return results;
    }

    /**
     * 解密某个值
     *
     * @param request
     * @param parmValue
     * @return
     */
    public static String decryptParmValue(HttpServletRequest request, String parmValue) {
        HttpSession session = request.getSession();
        String rtnValue = parmValue;
        KeyPair keys = (KeyPair) session.getAttribute("login_password_encrypt_keypair");
        if (keys != null && !StringUtils.isBlank(rtnValue)) {
            try {
                rtnValue = JCryptionUtil.decrypt(rtnValue, keys);
                rtnValue = URLDecoder.decode(rtnValue, "UTF8");
            } catch (Exception var6) {
                System.out.println("解密发生错误");
            }
        }

        return rtnValue;
    }

    /**
     * 通过密钥对源数据进行加密
     *
     * @param publicKey
     * @param plainText
     * @return
     */
    public static String encryptByPublicKey(String publicKey, String plainText) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(hexStringToByteArray(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher;
        try {
            try {
                cipher = Cipher.getInstance("RSA/NONE/NoPadding");
            } catch (Exception var8) {
                cipher = Cipher.getInstance("RSA/NONE/NoPadding", provider);
            }
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);//, new SecureRandom()
        } catch (GeneralSecurityException var9) {
            throw new RuntimeException("RSA algorithm not supported", var9);
        }
        byte[] cipherData = cipher.doFinal(getBytes(plainText));
        return byteArrayToHexString(cipherData);
    }

    public static String encryptByPrivateKey(String privateKey, String plainText) throws Exception {
        PKCS8EncodedKeySpec x509EncodedKeySpec = new PKCS8EncodedKeySpec(hexStringToByteArray(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pubKey = keyFactory.generatePrivate(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);//, new SecureRandom()
        byte[] cipherData = cipher.doFinal(getBytes(plainText));
        return byteArrayToHexString(cipherData);
    }

    private static byte[] getBytes(String text) throws UnsupportedEncodingException {
        return text.getBytes("utf-8");
    }

    /**
     * 通过私钥对加密后的数据解密
     *
     * @param publicKey
     * @param text
     * @return
     */
    public static String decryptByPublicKey(String publicKey, String text) throws Exception {
        byte[] cipherData = hexStringToByteArray(text);
        X509EncodedKeySpec priPKCS8 = new X509EncodedKeySpec(hexStringToByteArray(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey priKey = keyFactory.generatePublic(priPKCS8);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey, new SecureRandom());
        byte[] plainData = cipher.doFinal(cipherData);
        return new String(plainData, "utf-8");
    }

    public static String decryptByPrivateKey(String privateKey, String text) throws Exception {
        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(hexStringToByteArray(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey priKey = keyFactory.generatePrivate(priPKCS8);
        Cipher cipher;
        try {
            try {
                cipher = Cipher.getInstance("RSA/NONE/NoPadding");
            } catch (Exception var8) {
                cipher = Cipher.getInstance("RSA/NONE/NoPadding", provider);
            }
            cipher.init(Cipher.DECRYPT_MODE, priKey);//, new SecureRandom()
        } catch (GeneralSecurityException var9) {
            throw new RuntimeException("RSA algorithm not supported", var9);
        }
        byte[] plainData = cipher.doFinal(hexStringToByteArray(text));
        return new String(plainData, "utf-8");
    }


    /**
     * 根据公私钥进行加/解密
     * 输出结果：
     * PublicKey：
     * {"e":"10001","n":"8a2b6470b93fda982f85a26df41e1d60df25dfb433a2459133e5d10076bafef10e0559c6d2cfc4979368e05d2fc0f09732c71953e00f9a6f3d7de6cc811aa875","maxdigits":"67"}
     * PrivateKey：
     * {"e":"2970201c6a828b058f630db6da3ad9e6bea5f6346e33e1974db04401569a7870d29f2c09bd0a7a8a1142d776809eb528e15b7c1e4d854adf49ab1235aa371621","n":"8a2b6470b93fda982f85a26df41e1d60df25dfb433a2459133e5d10076bafef10e0559c6d2cfc4979368e05d2fc0f09732c71953e00f9a6f3d7de6cc811aa875","maxdigits":"67"}
     * privateKey：30820153020100300d06092a864886f70d01010105000482013d308201390201000241008a2b6470b93fda982f85a26df41e1d60df25dfb433a2459133e5d10076bafef10e0559c6d2cfc4979368e05d2fc0f09732c71953e00f9a6f3d7de6cc811aa875020301000102402970201c6a828b058f630db6da3ad9e6bea5f6346e33e1974db04401569a7870d29f2c09bd0a7a8a1142d776809eb528e15b7c1e4d854adf49ab1235aa371621022100df5c45ba27b1c99d07837909404dfeb973b26362c88e800ba63fd33fa5581c290221009e5c32b5f2f8aee4faeec249a8658b96baa928e67b3d514b22ed6ddde476b36d02203e4ed53caada13adf46c9e95101531dbb604ab68e11daf669087f97c25b9c09102207a7406ce854c614934f4ad0df2065b933951970bea5e36df67e9badc2b4ed25d02206ab557297f312b46fad1002ebc8b91f2a1f9d57fb754c08c93e11ad7deaad020
     * publicKey：305c300d06092a864886f70d0101010500034b0030480241008a2b6470b93fda982f85a26df41e1d60df25dfb433a2459133e5d10076bafef10e0559c6d2cfc4979368e05d2fc0f09732c71953e00f9a6f3d7de6cc811aa8750203010001
     * encryptByPublicKey：
     * 0e141157016a77edfb080007ada6a4be793430ba218a8085c962196760e2162e9e4738acb6dc0ac10cbd750088a222acc5ef4bdde797e173be5df44cdc2becdd
     * decryptByPrivateKey：
     * 12345678
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        KeyPair keypair = generateKeypair(512);
        System.out.println("PublicKey：");
        String publicKeyToString = keyPairPublicKeyToString(keypair, 512);
        System.out.println(publicKeyToString);
        System.out.println("PrivateKey：");
        String privateKeyToString = keyPairPrivateKeyToString(keypair, 512);
        System.out.println(privateKeyToString);
        String privateKey = byteArrayToHexString(keypair.getPrivate().getEncoded());
        String publicKey = byteArrayToHexString(keypair.getPublic().getEncoded());
        System.out.println("privateKey：" + privateKey);
        System.out.println("publicKey：" + publicKey);
//        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
//        String pass = br.readLine();
        System.out.println("encryptByPublicKey：");
        String pass = encryptByPublicKey(publicKey, "12345678");
        System.out.println(pass);
//        String decrypt = decrypt(pass, keypair);
//        System.out.println(decrypt);
        System.out.println("decryptByPrivateKey：");
        String decrypt = decryptByPrivateKey(privateKey, pass);
        System.out.println(decrypt);
    }


}

