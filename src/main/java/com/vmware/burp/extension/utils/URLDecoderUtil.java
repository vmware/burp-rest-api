package com.vmware.burp.extension.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.regex.Pattern;

public class URLDecoderUtil {

    // Regex pattern to validate hexadecimal sequences in URLs
    private static final Pattern HEX_PATTERN = Pattern.compile("%[0-9A-Fa-f]{2}");

    public static String safeDecode(String input) throws UnsupportedEncodingException {
        // Validate hexadecimal sequences

        StringBuffer decodedInput = new StringBuffer();

        if (input.contains("%") && !HEX_PATTERN.matcher(input).find()) {
            
            String[] splittedInput = input.split("%");
            for (String partialInput : splittedInput) {
                if (!HEX_PATTERN.matcher("%" + partialInput).find()){
                    decodedInput.append("%" + partialInput);
                }else{
                    decodedInput.append(URLDecoder.decode("%" + partialInput, "UTF-8"));
                }
            }
            
        }else{
            decodedInput.append(URLDecoder.decode(input, "UTF-8"));
        }
        
        // Decode the input
        return decodedInput.toString();
    }
}
