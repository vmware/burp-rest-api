package com.vmware.burp.extension.filter;

import com.vmware.burp.extension.config.SwaggerConfig;
import com.vmware.burp.extension.service.BurpService;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class ApiKeyFilter implements Filter {

    private final BurpService service;

    public ApiKeyFilter(BurpService service) {
        this.service = service;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String apiKey = service.getAPIKey();

        if (apiKey != null) {
            String apikeyHeader = request.getHeader(SwaggerConfig.API_KEY_HEADER);

            if (isValidApiKey(apiKey, apikeyHeader)) {
                filterChain.doFilter(request, response);
            }
            else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,"Missing API-KEY header or wrong value");
                return;
            }
        }
        else {
            filterChain.doFilter(request, response);
        }
    }

    // constant-time equals is provided by MessageDigest.isEqual
    private boolean isValidApiKey(String apiKey, String apikeyHeader) {

        if (apikeyHeader == null)
            return false;

        return MessageDigest.isEqual(apiKey.getBytes(StandardCharsets.UTF_8), apikeyHeader.getBytes(StandardCharsets.UTF_8));
    }

}
