/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.utils;

import burp.IHttpRequestResponse;
import burp.LegacyBurpExtender;
import com.vmware.burp.extension.domain.Config;
import com.vmware.burp.extension.domain.ConfigItem;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class Utils {

   public static Map<String, String> convertConfigurationListToMap(Config config) {
      Map<String, String> configMap = new HashMap<>();
      for (ConfigItem configItem : config.getConfiguration()) {
         configMap.put(configItem.getProperty(), configItem.getValue());
      }
      return configMap;
   }

   public static IHttpRequestResponse[] getSiteMapWrapper(String urlPrefix) throws MalformedURLException {
      URL target = new URL(urlPrefix);
      boolean isHttps = target.getProtocol().equalsIgnoreCase("HTTPS");
      int targetPort = target.getPort() != -1 ? target.getPort() : (isHttps ? 443 : 80);
      if(targetPort == 80 || targetPort == 443){
         return LegacyBurpExtender.getInstance().getCallbacks().getSiteMap(Utils.convertURLToStringWithoutPort(target));
      }else {
         return LegacyBurpExtender.getInstance().getCallbacks().getSiteMap(urlPrefix);
      }
   }

   public static String convertURLToStringWithoutPort(URL url) {
      try {
         return new URL(url.getProtocol(), url.getHost(), url.getFile()).toString();
      } catch (MalformedURLException e) {
         return null;
      }
   }
}
