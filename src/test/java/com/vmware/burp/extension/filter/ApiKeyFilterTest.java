package com.vmware.burp.extension.filter;

import com.vmware.burp.extension.config.SwaggerConfig;
import com.vmware.burp.extension.service.BurpService;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class ApiKeyFilterTest {

    /**
     * Requesting the protected path /burp/*
     */
    @Test
    public void whenAPIKeyIsDefinedAndRequestedProtectedURIWithoutHeader_ResponseIs403() throws ServletException, IOException {

        BurpService service = Mockito.mock(BurpService.class);
        Mockito.when(service.getAPIKey()).thenReturn("test-api-key");

        ApiKeyFilter customURLFilter = new ApiKeyFilter(service);

        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        Mockito.when(req.getRequestURI()).then(invocation -> {return "/burp/configuration";});

        customURLFilter.doFilter(req, res, chain);
        Assertions.assertEquals(res.getStatus(), 403);
    }

    @Test
    public void whenAPIKeyNotDefinedAndRequestProtectedURIWithoutHeader_ResponseIsNot403() throws ServletException, IOException {

        BurpService service = Mockito.mock(BurpService.class);

        ApiKeyFilter customURLFilter = new ApiKeyFilter(service);

        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        Mockito.when(req.getRequestURI()).then(invocation -> {return "/burp/configuration";});

        customURLFilter.doFilter(req, res, chain);
        Assertions.assertNotEquals(res.getStatus(), 403);
    }

    @Test
    public void whenAPIKeyDefinedAndRequestProtectedURIWithHeader_ResponseIs200() throws ServletException, IOException {

        BurpService service = Mockito.mock(BurpService.class);
        Mockito.when(service.getAPIKey()).thenReturn("test-api-key");

        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        Mockito.when(req.getHeader(SwaggerConfig.API_KEY_HEADER)).thenReturn("test-api-key");

        MockHttpServletResponse res = new MockHttpServletResponse();

        MockFilterChain chain = new MockFilterChain();
        Mockito.when(req.getRequestURI()).then(invocation -> {return "/burp/versions";});

        ApiKeyFilter customURLFilter = new ApiKeyFilter(service);

        customURLFilter.doFilter(req, res, chain);
        Assertions.assertEquals(res.getStatus(), 200);
    }
}
