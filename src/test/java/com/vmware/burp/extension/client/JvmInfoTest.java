package com.vmware.burp.extension.client;

import org.junit.jupiter.api.Test;

public class JvmInfoTest {
    @Test
    void printJvmInfo() {
        System.out.println("Java version: " + System.getProperty("java.version"));
        System.out.println("Java home: " + System.getProperty("java.home"));
        System.out.println("User: " + System.getProperty("user.name"));
        System.out.println("User home: " + System.getProperty("user.home"));
    }
} 