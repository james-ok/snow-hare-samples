package co.ll4.snowhare.samples.utils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA算法工具类
 * 加密/解密/签名/验签
 *
 * 公钥加密，私钥解密
 * 私钥签名，公钥验签
 *
 * 加密的作用：防泄密
 * 签名的作用：防篡改
 * @author james
 * @email soeasyjava@163.com
 * @date 2022/5/25 4:21 下午
 */
public class RSAUtils {

    // 加解密算法
    public static final String ALGORITHM = "RSA";
    // 签名算法 MD5WithRSA/SHA256WithRSA
    public static final String SIGN_ALGORITHM = "SHA256WithRSA";
    // 字符编码
    public static final String CHARSET = "UTF-8";
    // key长度
    public static final int KEY_SIZE = 1024;
    // key长度
    public static final int MAX_ENCRYPT_BLOCK = 117;
    // key长度
    public static final int MAX_DECRYPT_BLOCK = KEY_SIZE / 8;

    // 以下公私钥用于测试
    private static final String publicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApkuDPnV1a1KHyjh2Mbgjk/5qRYOCNeOfrtRilEpO7y8aoOjo2LpHeJrTwLjUa/Lix40NeA43AP6gSX6oN2Pt3T/owLzX9Np3CsXC6ux4RLzYeb4y+H2FHyPBx5A7CPxWAXDKniInxP39sniqwpBiXHsKdJhfCzbY1WC1Kt6F7sSh4T5NnaLl1JXlBH+bfKzcR7kPA/c3fqUBcxNz1lwH772tw29KQwUOUs8mQ2Bf0tsIjxm/b0Z81rqCsTQY5xKsBQ4db87z8t5Ad2/Jt18armkFcX9mUBNJ2RHmLtbnrIeR3W+ztG/ayzOqZAUNallBrqH5pBNrMEb+7pDdlYwtLI2ilrk9i1D5U6qOW0WYx+PfeF5T7bv+TkZG+VTNLCuafMM1kEx+Wt9l3Ad1jcxpvNTpT6RkwA/89fH68G/DV1N8+8ZQB7htnnncoUf7G+7BKAT5swRF8fMN47C6ghkeOoOB0WPeMYWcWGQXc9ZTSh/iqBAGp0qqWHO6UX6fLru6bQnj3Fqotte0JBvdzW1GnMchrCwN7FUgEPRGqiUmTeGDTWW5igeuo6R72GoZbMuP3q2+hTAKRG4IzKPdckH0eRDwSCxQwrvg2kZbPNIiRxHKT3u3S2r2VQf2yAif86VueopzRNn7hqI28SN/XP2HVd2xY16SGTM6ZgQ66/EjK0kCAwEAAQ==";
    private static final String privateKey = "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";

    public static void main(String[] args) throws Exception {
        Map<String, String> keyPairMap = generateKey();
        System.out.println(keyPairMap.get("publicKey"));
        System.out.println(keyPairMap.get("privateKey"));

//        String data = "123456";
//        String encrypt = encrypt(publicKey, data);
//        System.out.println(encrypt);//m6SFv7RpeFzAgcDqSfqis7EGN2xea7Uu/gIYrJqGUf7UTFvHGlsrGNx4yGjLY1KkU1JOlz0eTlcHwFN2RFv4Ym24XWHu7ESyz1qlHmsKKvKtWojN0Xl4LBtLlsgv/eWZqe25xFTTfMbMBIK4ZlP9lLCGx8jTNSV4op9I2AY4crW+F04oCvmSpgbCIVQlNW40xrc2Tb22t0/hwfrD4nzcnncyz2kXHllEv97OtrKifmXDCfCf9edPJw6RX0NuRgyI8SLT8bylNqJ53quybUUr1e01Z9cZqmVgZg0uPJPkWaVIuCRu5q2SNQ7Y/pT8YQK1Crlnl6LFYZo8E8SPczscfd062IdHN9RpvOTR9V1mKJwfY6k2jIOdaYIEE2z/sllgmaIgLLmX08OCTj8cK+iz8DxTLo4LOXyTEGY2bUQw8CZsLjdBCl7S7pa6mryWG8STAf7W3wno1zuLz91KbnP0jT+TjyFVC6EpLxPxjfWJQ0fRJSPwUsd5WNck9n9NdN0T9Kascl3zgT//Glb2sbHGpSLDVN9+chdR9f4GzsSmIpswayr6o/fFJKe3KmiB/mu3aW6TIKaQogek45vcIZ/RDKtxEI3we6y+Lzq/nToF35npdMCqzHS24N/iImrwuLXm9Um+im1Wb9gFglMflVLLhwBr73uNcJA7MsaLrp+5WUA=


//        String encryptDate = "m6SFv7RpeFzAgcDqSfqis7EGN2xea7Uu/gIYrJqGUf7UTFvHGlsrGNx4yGjLY1KkU1JOlz0eTlcHwFN2RFv4Ym24XWHu7ESyz1qlHmsKKvKtWojN0Xl4LBtLlsgv/eWZqe25xFTTfMbMBIK4ZlP9lLCGx8jTNSV4op9I2AY4crW+F04oCvmSpgbCIVQlNW40xrc2Tb22t0/hwfrD4nzcnncyz2kXHllEv97OtrKifmXDCfCf9edPJw6RX0NuRgyI8SLT8bylNqJ53quybUUr1e01Z9cZqmVgZg0uPJPkWaVIuCRu5q2SNQ7Y/pT8YQK1Crlnl6LFYZo8E8SPczscfd062IdHN9RpvOTR9V1mKJwfY6k2jIOdaYIEE2z/sllgmaIgLLmX08OCTj8cK+iz8DxTLo4LOXyTEGY2bUQw8CZsLjdBCl7S7pa6mryWG8STAf7W3wno1zuLz91KbnP0jT+TjyFVC6EpLxPxjfWJQ0fRJSPwUsd5WNck9n9NdN0T9Kascl3zgT//Glb2sbHGpSLDVN9+chdR9f4GzsSmIpswayr6o/fFJKe3KmiB/mu3aW6TIKaQogek45vcIZ/RDKtxEI3we6y+Lzq/nToF35npdMCqzHS24N/iImrwuLXm9Um+im1Wb9gFglMflVLLhwBr73uNcJA7MsaLrp+5WUA=";
//        String decrypt = decrypt(privateKey, encryptDate);
//        System.out.println(decrypt);


//        String data = "1234567890";


//        String sign = sign(privateKey, data);
//        System.out.println(sign); // Z0LjNmwscHLjXQKsoxvMR1NN5Htrno4P1Ypi+HyGhDq10GgrecAhmMZ/IkfulMnVGusGVrTcZ7xM1JAvBJ2q1IuBEr0+qL65mEw8vr7G4uW2V+f62RigbolI2/ITzM5M2UEvFAJahD8iqLC9WX8hjT3isjk+1ZKB/mu2+McWM/mrkatPUu/aNdBxu8f3CRDMcGkXSsDEqCfGyBjehm2I8FayUzMUK5Jw7mK2odRERM0xEmPhr3IhZoH0cDgBc4tcYrQbFUBCjkii+cadL2bW/BwvqzCIqa8YM2WHr50fTXnz3dm/m3n/7JDbLO43pJ3BiNKzgiY0wBy+22ld7Oe1lhVAxLgoHslaDCMXhRiqw6YTKxF90d5K+o+S1W0TpRD5AvhIddhoCtAKSconYkAx0QdiGkkQrZbdt8KEFFeHezVtf4GuFzLOtrxmiNCAhknsHD5ls9qNcdWgOt5YdcOHrbUQrphDzGvodcP4YtiOhykminJ21D6vOMKXTnMZ8q9j6SCiV8/T9zc+b4ag3gWf+UR3pMh3xf2jG2zaSrnUQNT9Fs6bLdeOVqwcYK9CwT9JRehZPh9tNkt8Di2aoTc5x63j8Urndas3U4Uj7/xRKuU+iI+4CI6vWJpkkG7KmgiHVX6yXV0v/p0DXiwD5e8SyJV1PoaPIVI/ZkcdXivI0W8=


//        boolean verify = verify(publicKey, data, "Z0LjNmwscHLjXQKsoxvMR1NN5Htrno4P1Ypi+HyGhDq10GgrecAhmMZ/IkfulMnVGusGVrTcZ7xM1JAvBJ2q1IuBEr0+qL65mEw8vr7G4uW2V+f62RigbolI2/ITzM5M2UEvFAJahD8iqLC9WX8hjT3isjk+1ZKB/mu2+McWM/mrkatPUu/aNdBxu8f3CRDMcGkXSsDEqCfGyBjehm2I8FayUzMUK5Jw7mK2odRERM0xEmPhr3IhZoH0cDgBc4tcYrQbFUBCjkii+cadL2bW/BwvqzCIqa8YM2WHr50fTXnz3dm/m3n/7JDbLO43pJ3BiNKzgiY0wBy+22ld7Oe1lhVAxLgoHslaDCMXhRiqw6YTKxF90d5K+o+S1W0TpRD5AvhIddhoCtAKSconYkAx0QdiGkkQrZbdt8KEFFeHezVtf4GuFzLOtrxmiNCAhknsHD5ls9qNcdWgOt5YdcOHrbUQrphDzGvodcP4YtiOhykminJ21D6vOMKXTnMZ8q9j6SCiV8/T9zc+b4ag3gWf+UR3pMh3xf2jG2zaSrnUQNT9Fs6bLdeOVqwcYK9CwT9JRehZPh9tNkt8Di2aoTc5x63j8Urndas3U4Uj7/xRKuU+iI+4CI6vWJpkkG7KmgiHVX6yXV0v/p0DXiwD5e8SyJV1PoaPIVI/ZkcdXivI0W8=");
//        System.out.println(verify);

    }

    /**
     * 生成密钥
     * @return
     * @throws Exception
     */
    public static Map<String,String> generateKey() throws Exception {
        Map<String,String> keyPairMap = new HashMap<>();
        try {
            // 实例化密钥对生成器，指定密钥算法
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            // 初始化密钥长度
            keyPairGenerator.initialize(KEY_SIZE);
            // 生成密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            // 获取公钥及私钥
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            // 对公钥及私钥进行base64编码
            String publicKeyBase64Str = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyBase64Str = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            keyPairMap.put("publicKey",publicKeyBase64Str);
            keyPairMap.put("privateKey",privateKeyBase64Str);
            return keyPairMap;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("密钥生成失败");
        }
    }


    /**
     * 公钥加密
     * @param publicKeyBase64Str
     * @param data
     * @return
     */
    public static String encrypt(String publicKeyBase64Str,String data) throws Exception {
        try {
            // 将编码后对公钥字符串解码
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64Str);
            // 创建KeySpec
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 实例化Key创建工厂，指定算法
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            // 生成公钥
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            // 创建加密对象，算法和key创建工厂一致
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            // 初始化加密/解密模式，并传入公钥
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            // 加密（分段加密）
            // Cipher 提供加解密 API，其中 RSA 非对称加密解密内容长度是有限制的，加密长度不超过 117Byte，解密长度不超过 128Byte。
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            int length = dataBytes.length;
            int offset = 0;
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (int i = 0; length - offset > 0; offset = i * MAX_ENCRYPT_BLOCK) {
                byte[] cache;
                // 如果当前偏移量offset到字节数据末尾大小大于最大加密长度，则继续分段加密
                // 否则为最后一次分段加密，从当前偏移量知道数据末尾
                if (length - offset > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(dataBytes,offset,MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(dataBytes,offset,length - offset);
                }
                // 将分段加密后到数据写入到内存二进制流
                os.write(cache,0,cache.length);
                i++;
            }
            // 得到加密后到二进制流
            byte[] bytes = os.toByteArray();
            // 关闭流
            os.close();
            // base64编码并返回
            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("加密失败");
        }
    }


    /**
     * 私钥解密
     * @param privateKeyBase64Str
     * @param data
     * @return
     * @throws Exception
     */
    public static String decrypt(String privateKeyBase64Str,String data) throws Exception {
        try {
            // 解密私钥字符串
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64Str);
            // 创建KeySpec
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            // 实例化Key创建工厂，指定算法
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            // 生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            // 创建加密对象，算法和key创建工厂一致
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            // 初始化加密/解密模式，并传入公钥
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            // 解密（分段解密）
            // Cipher 提供加解密 API，其中 RSA 非对称加密解密内容长度是有限制的，加密长度不超过 117Byte，解密长度不超过 128Byte。
            // 解密长度这只是针对密钥长度为1024字节的密钥，如果其他长度，解密长度需要 = 密钥长度 / 8，例如：length = 4096 / 8 = 512
            byte[] dataBytes = Base64.getDecoder().decode(data);
            int length = dataBytes.length;
            int offset = 0;
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (int i = 0; length - offset > 0; offset = i * MAX_DECRYPT_BLOCK) {
                byte[] cache;
                // 如果当前偏移量offset到字节数据末尾大小大于最大加密长度，则继续分段加密
                // 否则为最后一次分段加密，从当前偏移量知道数据末尾
                if (length - offset > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(dataBytes,offset,MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(dataBytes,offset,length - offset);
                }
                // 将分段加密后到数据写入到内存二进制流
                os.write(cache,0,cache.length);
                i++;
            }
            // 得到加密后到二进制流
            byte[] bytes = os.toByteArray();
            // 关闭流
            os.close();
            // base64编码并返回
            return new String(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("解密失败");
        }
    }


    /**
     * 私钥签名
     * @param privateKeyBase64Str
     * @param data
     * @param signType
     * @param charset
     * @return
     * @throws Exception
     */
    public static String sign(String privateKeyBase64Str,String data,String signType,String charset) throws Exception {
        try {
            // 解密私钥字符串
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64Str);
            // 创建KeySpec
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            // 实例化Key创建工厂，指定算法
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            // 生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            // 创建签名对象
            Signature signature = Signature.getInstance(signType);
            // 初始化签名私钥
            signature.initSign(privateKey);
            // 更新需要签名的数据
            signature.update(data.getBytes(charset));
            // 执行签名
            byte[] bytes = signature.sign();
            // base64编码并返回
            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("解密失败");
        }
    }


    /**
     *
     * @param privateKeyBase64Str
     * @param data
     * @return
     * @throws Exception
     */
    public static String sign(String privateKeyBase64Str,String data) throws Exception {
        return sign(privateKeyBase64Str,data,SIGN_ALGORITHM,CHARSET);
    }

    /**
     * 公钥验签
     * @param publicKeyBase64Str
     * @param data
     * @param sign
     * @param signType
     * @param charset
     * @return
     * @throws Exception
     */
    public static boolean verify(String publicKeyBase64Str,String data,String sign,String signType,String charset) throws Exception {
        try {
            // 解密私钥字符串
            byte[] privateKeyBytes = Base64.getDecoder().decode(publicKeyBase64Str);
            // 创建KeySpec
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(privateKeyBytes);
            // 实例化Key创建工厂，指定算法
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            // 生成私钥
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            // 创建签名对象
            Signature signature = Signature.getInstance(signType);
            // 初始化签名私钥
            signature.initVerify(publicKey);
            // 更新需要签名的数据
            signature.update(data.getBytes(charset));
            // 执行签名
            byte[] signBytes = Base64.getDecoder().decode(sign);
            return signature.verify(signBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("验签失败");
        }
    }

    /**
     *
     * @param publicKeyBase64Str
     * @param data
     * @param sign
     * @return
     * @throws Exception
     */
    public static boolean verify(String publicKeyBase64Str,String data,String sign) throws Exception {
        return verify(publicKeyBase64Str,data,sign,SIGN_ALGORITHM,CHARSET);
    }
    /**
     * 读取私钥文件内容
     * @param path
     * @return
     * @throws IOException
     */
    public static String readPrivateKeyFile(String path) throws IOException {
        // 读取文件
        String key = new String(Files.readAllBytes(Paths.get(path)),StandardCharsets.UTF_8);
        String privateKeyCode = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("\n", "")
                .replace("-----END PRIVATE KEY-----", "");
        return privateKeyCode;
    }

    /**
     * 读取公钥文件内容
     * @param path
     * @return
     * @throws IOException
     */
    public static String readPublicKeyFile(String path) throws IOException {
        String key = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        String publicKeyCode = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        return publicKeyCode;
    }

}
