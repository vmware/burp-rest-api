package com.vmware.burp.extension.client;

import com.vmware.burp.extension.service.BurpService;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;

@SpringBootTest (properties = {"java.awt.headless=true"})
@RunWith(SpringRunner.class)
public class ArgumentsTest {

    @Test
    public void ApiKeyArgumentsSetsApiKeyFieldInBurpService() throws IOException, URISyntaxException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {

        ApplicationArguments defaultApplicationArguments = new DefaultApplicationArguments("--apikey=test-api-key");
        BurpService service = new BurpService(defaultApplicationArguments, true, null, null);
        Assertions.assertTrue(service.getAPIKey().equals("test-api-key"));
    }

    @Test
    public void NoApiKeyArguments_ApiKeyFieldIsNull() throws IOException, URISyntaxException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {

        ApplicationArguments defaultApplicationArguments = new DefaultApplicationArguments("");
        BurpService service = new BurpService(defaultApplicationArguments, true, null, null);
        Assertions.assertTrue(service.getAPIKey() == null);
    }

}
