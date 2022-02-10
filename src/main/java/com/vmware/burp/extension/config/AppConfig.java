package com.vmware.burp.extension.config;


import com.vmware.burp.extension.filter.ApiKeyFilter;
import com.vmware.burp.extension.service.BurpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;



@Configuration
@Import(SwaggerConfig.class)
public class AppConfig {

    @Autowired
    BurpService service;

    @Bean
    public FilterRegistrationBean<ApiKeyFilter> filterRegistrationBean() {
        FilterRegistrationBean <ApiKeyFilter> registrationBean = new FilterRegistrationBean();
        ApiKeyFilter apiKeyFilter = new ApiKeyFilter(service);
        registrationBean.setFilter(apiKeyFilter);
        registrationBean.addUrlPatterns("/burp/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }
}

