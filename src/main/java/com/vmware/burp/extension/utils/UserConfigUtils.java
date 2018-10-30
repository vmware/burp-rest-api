/*
 * Copyright (c) 2018 Doyensec LLC.
 */
package com.vmware.burp.extension.utils;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.util.FileCopyUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class helps in injecting custom extensions to user config through the burp-rest-api command line.
 */
public class UserConfigUtils {
    /**
     * Extension POJO representing the Burp configuration for a given extension.
     */
    public static class Extension {
        private static Map<String, String> pluginExtToType = new HashMap<String, String>() {{
            put("jar", "java");
            put("rb", "ruby");
            put("py", "python");
        }};
        private String errors = "console";
        private String output = "console";
        private boolean loaded = true;
        private String extension_file;
        private String extension_type;
        private String name;

        public Extension() {}

        /**
         * Build a new Extension POJO from a path.
         * @param path representing the location of a given Burp extension
         */
        public Extension(String path) {
            extension_type = pluginExtToType.get(getFileExtension(path));
            name = path;
            extension_file = path;
        }

        private static String getFileExtension(String name) {
            int lastIndexOf = name.lastIndexOf(".");
            if (lastIndexOf == -1) {
                return ""; // empty extension
            }
            return name.substring(lastIndexOf + 1);
        }
    }

    private List<Extension> extensions = new ArrayList<>();

    /**
     * Register a new Burp extension
     * @param path representing the location of a given Burp extension
     */
    public void registerBurpExtension(String path) {
        extensions.add(new Extension(path));
    }


    /**
     * Given a userconfig, copy it in a new temporary file and injects all the registered extensions
     * @param path a userconfig path to be injected
     * @return a new userconfig path
     * @throws IOException when one of the two userconfig is not accessible/writable/creatable
     */
    public String injectExtensions(String path) throws IOException {
        Path userOptionsTempFile = Files.createTempFile("user-options_", ".json");
        FileCopyUtils.copy(new File(path), userOptionsTempFile.toFile());

        //addBurpExtensions here to the temporary file and return the handle to the new temporary file
        //- read all file in in jackson object
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        JsonNode tree = objectMapper.readTree(userOptionsTempFile.toFile());
        //- inject the burp extensions here inside the user configuration
        JsonNode user_options = safeGet(objectMapper, tree, "user_options");
        JsonNode extender = safeGet(objectMapper, user_options, "extender");
        JsonNode extension = extender.get("extensions");
        if (!extension.isArray()) {
            ArrayNode array = objectMapper.createArrayNode();
            ((ObjectNode)extender).replace("extensions", array);
            extension = array;
        }
        for (Extension e : extensions) {
            ((ArrayNode) extension).addPOJO(e);
        }
        //- write the jackson configuration inside the temporary user configuration
        objectMapper.writer(new DefaultPrettyPrinter()).writeValue(userOptionsTempFile.toFile(), tree);

        userOptionsTempFile.toFile().deleteOnExit();
        return userOptionsTempFile.toAbsolutePath().toString();
    }

    private static JsonNode safeGet(ObjectMapper objectMapper, JsonNode root, String path) {
        JsonNode newNode = root.get(path);
        if (newNode.isMissingNode()) {
            ObjectNode addNode = objectMapper.createObjectNode();
            ((ObjectNode)root).replace(path, addNode);
        }
        return root.get(path);
    }

}
