package com.vmware.burp.extension.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.regex.Pattern;

public class URLDecoderUtil {

    // Regex pattern to validate hexadecimal sequences in URLs
    private static final Pattern HEX_PATTERN = Pattern.compile("%[0-9A-Fa-f]{2}");

    public static String safeDecode(String input) throws UnsupportedEncodingException {
        // Validate hexadecimal sequences
        if (input.contains("%") && !HEX_PATTERN.matcher(input).find()) {
            throw new IllegalArgumentException("Invalid URL encoding in input: " + input);
        }
        
        // Decode the input
        return URLDecoder.decode(input, "UTF-8");
    }
}
