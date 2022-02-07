package com.vmware.burp.extension.filter;

import com.vmware.burp.extension.config.SwaggerConfig;
import com.vmware.burp.extension.service.BurpService;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class APIKeyFilter implements Filter {

    private final BurpService service;

    public APIKeyFilter(BurpService service) {
        this.service = service;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (service.getAPIKey() != null) {
            String apikeyHeader = request.getHeader(SwaggerConfig.API_KEY_HEADER);
            if (service.getAPIKey().equals(apikeyHeader)) {
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

}
