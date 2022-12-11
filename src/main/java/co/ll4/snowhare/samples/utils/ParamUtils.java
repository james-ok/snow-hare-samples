package co.ll4.snowhare.samples.utils;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.util.*;

/**
 * @author james
 * @email soeasyjava@163.com
 * @date 2022/12/1 2:44 下午
 */
public class ParamUtils {


    /**
     * 排序并序列化参数
     * @param paramMap
     * @param ignoreParams
     * @return
     */
    public static String sortedSerializeParams(Map<String,String> paramMap,String... ignoreParams) {
        HashSet<String> sortedKeys = new HashSet<>(paramMap.keySet());
        List<String> ignoreParamList = Arrays.asList(ignoreParams);
        StringBuilder sb = new StringBuilder();
        for (String key : sortedKeys) {
            String value = paramMap.get(key);
            // 忽略指定key
            if (ignoreParamList.contains(key)
                    || value == null
                    || "".equals(value)) {
                continue;
            }
            sb.append(key).append("=").append(value).append("&");
        }
        // 删除最后一个&
        sb.delete(sb.length()-1, sb.length());
        return sb.toString();
    }



    public static String encodeSerializeParams(Map<String,String> paramMap) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        for (String key : paramMap.keySet()) {
            String value = paramMap.get(key);
            if (value == null || "".equals(value)) {
                continue;
            }
            sb.append(key).append("=").append(URLEncoder.encode(value,"UTF-8")).append("&");
        }
        // 删除最后一个&
        sb.delete(sb.length()-1, sb.length());
        return sb.toString();
    }

    /**
     * 将对象转换为map
     * @param obj
     * @return
     * @throws IllegalAccessException
     */
    public static Map<String,String> obj2Map(Object obj) throws IllegalAccessException {
        Map<String,String> resultMap = new HashMap<>();
        if (obj == null) {
            return resultMap;
        }
        Class clazz = obj.getClass();
        getField(obj,clazz,resultMap);
        return resultMap;
    }

    /**
     * 递归解析参数
     * @param obj
     * @param clazz
     * @param map
     */
    private static void getField(Object obj,Class clazz,Map<String,String> map) throws IllegalAccessException {
        if (clazz == null) {
            return;
        }
        Field[] fields = clazz.getDeclaredFields();
        for (Field field : fields) {
            field.setAccessible(true);
            map.put(field.getName(), String.valueOf(field.get(obj)));
        }
        getField(obj,clazz.getSuperclass(),map);
    }

}
