package co.ll4.snowhare.samples;

import co.ll4.snowhare.samples.constants.SnowHareConstants;
import co.ll4.snowhare.samples.utils.ParamUtils;
import co.ll4.snowhare.samples.utils.RSAUtils;
import com.alibaba.fastjson.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author james
 * @email soeasyjava@163.com
 * @date 2022/12/6 9:04 下午
 */
public class OpenApiTests {




    public static void main(String[] args) throws Exception {
        create();
        //query();
        //update();
        //delete();
    }


    private static void delete() throws Exception {
        Map<String,String> content = new HashMap<>();
        content.put("id","9");
        String contentStr = JSONObject.toJSONString(content);
        // 平台公钥加密
        String encrypt = RSAUtils.encrypt(SnowHareConstants.platformPublicKey, contentStr);

        Map<String,String> params = new HashMap<>();
        params.put("appId","1568654be8634ab890b2db09e5128cda");
        params.put("method","open.api.shortUrl.delete");
        params.put("version","1.0");
        params.put("requestId", UUID.randomUUID().toString());
        params.put("charset","UTF-8");
        params.put("signType","RSA2");
        params.put("content",encrypt);

        // 商户私钥签名
        String serializeParams = ParamUtils.sortedSerializeParams(params, "signType");
        String sign = RSAUtils.sign(SnowHareConstants.merchantPrivateKey, serializeParams);

        params.put("sign",sign);

        System.out.println("请求参数：" + params);

        // 这里需要注意：因为签名和加密content使用对是base64编码，内容可能会存在+号等特殊字符，
        // 所以ParamUtils.encodeSerializeParams(params)中对value值进行了URLEncode
        String ret = sendPostRequestByForm(SnowHareConstants.url, ParamUtils.encodeSerializeParams(params));
        System.out.println("请求响应：" + ret);

        JSONObject responseJson = JSONObject.parseObject(ret);
        if (responseJson.getInteger("code")!=0) {
            return;
        }
        // 这里验证签名只需要将加密内容进行验证
        boolean verify = RSAUtils.verify(SnowHareConstants.platformPublicKey, responseJson.getString("data"), responseJson.getString("sign"));
        if (!verify) {
            System.out.println("验签失败");
        }
        String data = responseJson.get("data").toString();
        System.out.println("返回数据，密文：" + data);
        String decrypt = RSAUtils.decrypt(SnowHareConstants.merchantPrivateKey, data);
        System.out.println("返回数据，明文：" + decrypt);
    }

    private static void update() throws Exception {
        Map<String,String> content = new HashMap<>();
        content.put("id","7");
        content.put("url","https://www.cnblogs.com/chen-lhx/p/5852296.html");
        String contentStr = JSONObject.toJSONString(content);
        // 平台公钥加密
        String encrypt = RSAUtils.encrypt(SnowHareConstants.platformPublicKey, contentStr);

        Map<String,String> params = new HashMap<>();
        params.put("appId","1568654be8634ab890b2db09e5128cda");
        params.put("method","open.api.shortUrl.update");
        params.put("version","1.0");
        params.put("requestId", UUID.randomUUID().toString());
        params.put("charset","UTF-8");
        params.put("signType","RSA2");
        params.put("content",encrypt);

        // 商户私钥签名
        String serializeParams = ParamUtils.sortedSerializeParams(params, "signType");
        String sign = RSAUtils.sign(SnowHareConstants.merchantPrivateKey, serializeParams);

        params.put("sign",sign);

        System.out.println("请求参数：" + params);

        // 这里需要注意：因为签名和加密content使用对是base64编码，内容可能会存在+号等特殊字符，
        // 所以ParamUtils.encodeSerializeParams(params)中对value值进行了URLEncode
        String ret = sendPostRequestByForm(SnowHareConstants.url, ParamUtils.encodeSerializeParams(params));
        System.out.println("请求响应：" + ret);

        JSONObject responseJson = JSONObject.parseObject(ret);

        if (responseJson.getInteger("code")!=0) {
            return;
        }
        // 这里验证签名只需要将加密内容进行验证
        boolean verify = RSAUtils.verify(SnowHareConstants.platformPublicKey, responseJson.getString("data"), responseJson.getString("sign"));
        if (!verify) {
            System.out.println("验签失败");
        }
        String data = responseJson.get("data").toString();
        System.out.println("返回数据，密文：" + data);
        String decrypt = RSAUtils.decrypt(SnowHareConstants.merchantPrivateKey, data);
        System.out.println("返回数据，明文：" + decrypt);
    }

    private static void query() throws Exception {
        Map<String,String> content = new HashMap<>();
        content.put("page","1");
        content.put("size","5");
        content.put("shortUrlCode","");
        content.put("urlDomain","");
        content.put("state","1");
        String contentStr = JSONObject.toJSONString(content);
        // 平台公钥加密
        String encrypt = RSAUtils.encrypt(SnowHareConstants.platformPublicKey, contentStr);

        Map<String,String> params = new HashMap<>();
        params.put("appId","1568654be8634ab890b2db09e5128cda");
        params.put("method","open.api.shortUrl.query");
        params.put("version","1.0");
        params.put("requestId", UUID.randomUUID().toString());
        params.put("charset","UTF-8");
        params.put("signType","RSA2");
        params.put("content",encrypt);

        // 商户私钥签名
        String serializeParams = ParamUtils.sortedSerializeParams(params, "signType");
        String sign = RSAUtils.sign(SnowHareConstants.merchantPrivateKey, serializeParams);

        params.put("sign",sign);

        System.out.println("请求参数：" + params);

        // 这里需要注意：因为签名和加密content使用对是base64编码，内容可能会存在+号等特殊字符，
        // 所以ParamUtils.encodeSerializeParams(params)中对value值进行了URLEncode
        String ret = sendPostRequestByForm(SnowHareConstants.url, ParamUtils.encodeSerializeParams(params));
        System.out.println("请求响应：" + ret);

        JSONObject responseJson = JSONObject.parseObject(ret);
        if (responseJson.getInteger("code")!=0) {
            return;
        }
        // 这里验证签名只需要将加密内容进行验证
        boolean verify = RSAUtils.verify(SnowHareConstants.platformPublicKey, responseJson.getString("data"), responseJson.getString("sign"));
        if (!verify) {
            System.out.println("验签失败");
        }
        String data = responseJson.get("data").toString();
        System.out.println("返回数据，密文：" + data);
        String decrypt = RSAUtils.decrypt(SnowHareConstants.merchantPrivateKey, data);
        System.out.println("返回数据，明文：" + decrypt);
    }

    private static void create() throws Exception {
        Map<String,String> content = new HashMap<>();
        content.put("url","https://help.aliyun.com/document_detail/27102.html?utm_content=g_1000230851&spm=5176.20966629.toubu.3.f2991ddcpxxvD1#title-4t2-r2t-5zw");

        String contentStr = JSONObject.toJSONString(content);
        // 平台公钥加密
        String encrypt = RSAUtils.encrypt(SnowHareConstants.platformPublicKey, contentStr);

        Map<String,String> params = new HashMap<>();
        params.put("appId","1568654be8634ab890b2db09e5128cda");
        params.put("method","open.api.shortUrl.create");
        params.put("version","1.0");
        params.put("requestId", UUID.randomUUID().toString());
        params.put("charset","UTF-8");
        params.put("signType","RSA2");
        params.put("content",encrypt);

        // 商户私钥签名
        String serializeParams = ParamUtils.sortedSerializeParams(params, "signType");
        String sign = RSAUtils.sign(SnowHareConstants.merchantPrivateKey, serializeParams);

        params.put("sign",sign);

        System.out.println("请求参数：" + params);

        // 这里需要注意：因为签名和加密content使用对是base64编码，内容可能会存在+号等特殊字符，
        // 所以ParamUtils.encodeSerializeParams(params)中对value值进行了URLEncode
        String ret = sendPostRequestByForm(SnowHareConstants.url, ParamUtils.encodeSerializeParams(params));
        System.out.println("请求响应：" + ret);

        JSONObject responseJson = JSONObject.parseObject(ret);
        if (responseJson.getInteger("code")!=0) {
            return;
        }
        // 这里验证签名只需要将加密内容进行验证
        boolean verify = RSAUtils.verify(SnowHareConstants.platformPublicKey, responseJson.getString("data"), responseJson.getString("sign"));
        if (!verify) {
            System.out.println("验签失败");
        }
        String data = responseJson.get("data").toString();
        System.out.println("返回数据，密文：" + data);
        String decrypt = RSAUtils.decrypt(SnowHareConstants.merchantPrivateKey, data);
        System.out.println("返回数据，明文：" + decrypt);

    }



    /**
     * 通过HttpURLConnection模拟post表单提交
     *
     * @param path
     * @param params 例如"name=zhangsan&age=21"
     * @return
     * @throws Exception
     */
    public static String sendPostRequestByForm(String path, String params) throws Exception{
        URL url = new URL(path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Accept","application/json");
        conn.setRequestMethod("POST");
        // 是否输入参数
        conn.setDoOutput(true);
        byte[] bypes = params.getBytes();
        conn.getOutputStream().write(bypes);
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        StringBuffer responseSb = new StringBuffer();
        String line = null;
        while ((line = reader.readLine()) != null) {
            responseSb.append(line.trim());
        }
        reader.close();
        return responseSb.toString().trim();
    }

}
