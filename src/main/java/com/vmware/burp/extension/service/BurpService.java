/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.service;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScanQueueItem;
import com.vmware.burp.extension.domain.Config;
import com.vmware.burp.extension.domain.ConfigItem;
import com.vmware.burp.extension.domain.HttpMessage;
import com.vmware.burp.extension.domain.ReportType;
import com.vmware.burp.extension.domain.ScanIssue;
import com.vmware.burp.extension.domain.internal.ScanQueueMap;
import com.vmware.burp.extension.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public class BurpService {
   private static final Logger log = LoggerFactory.getLogger(BurpService.class);
   private static final String PROJECT_FILE = "project-file";
   private static final String PROJECT_FILE_ARGUMENT = "--" + PROJECT_FILE + "=";
   private static final String CONFIG_FILE_ARGUMENT = "--config-file=";
   private static final String TEMPORARY_PROJECT_FILE_NAME = "temp-project.burp";
   private ScanQueueMap scans;

   @Value("${java.awt.headless}")
   private boolean awtHeadLessMode;

   @Autowired
   public BurpService(ApplicationArguments args, @Value("${headless.mode}") boolean headlessMode, @Value("${burp.edition}") String burpEdition)
         throws IOException {
      if (!headlessMode) {
         log.info("Setting java.awt.headless to false...");
         System.setProperty("java.awt.headless", Boolean.toString(false));
      }
      log.info("# of command line arguments received to Burp suite: {}", args.getSourceArgs().length);
      log.info("Launching the Burp suite ({} edition) in {} mode...", burpEdition, headlessMode ? "headless" : "UI");

      if (args.getSourceArgs().length == 0 || !args.containsOption(PROJECT_FILE)) {
         Resource defaultProjectOptionsFile = new ClassPathResource(
               "/static/burp-default-project-options.json");
         Resource defaultUserOptionsFile = new ClassPathResource(
               "/static/burp-default-user-options.json");

         Path projectOptionsTempFile = Files.createTempFile("project-options", ".json");
         Path userOptionsTempFile = Files.createTempFile("user-options", ".json");
         FileCopyUtils
               .copy(FileCopyUtils.copyToByteArray(defaultProjectOptionsFile.getInputStream()),
                     projectOptionsTempFile.toFile());
         FileCopyUtils.copy(FileCopyUtils.copyToByteArray(defaultUserOptionsFile.getInputStream()),
               userOptionsTempFile.toFile());

         // As of Burp 1.7.03 version, --project-file option is mandatory to launch the jar in CI/CD pipeline.
         // --config-file option is optional
         String projectFileArgument = PROJECT_FILE_ARGUMENT + TEMPORARY_PROJECT_FILE_NAME;
         String configFileArgumentWithProjectOptions =
               CONFIG_FILE_ARGUMENT + projectOptionsTempFile.toAbsolutePath();
         String configFileArgumentWithUserOptions =
               CONFIG_FILE_ARGUMENT + userOptionsTempFile.toAbsolutePath();

         // Free edition does not allow PROJECT_FILE_ARGUMENT
         String[] burpOptions;
         if (burpEdition.equalsIgnoreCase("free")) {
            burpOptions = new String[] { configFileArgumentWithProjectOptions, configFileArgumentWithUserOptions };
         } else {
            burpOptions = new String[] { projectFileArgument,
                  configFileArgumentWithProjectOptions, configFileArgumentWithUserOptions };
         }

         log.info("Launching the Burp suite with options: {}", Arrays.toString(burpOptions));
         burp.StartBurp.main(burpOptions);

         // Deletes the temporary project file while exiting the application.
         File file = new File(TEMPORARY_PROJECT_FILE_NAME);
         file.deleteOnExit();
         projectOptionsTempFile.toFile().deleteOnExit();
         userOptionsTempFile.toFile().deleteOnExit();
      } else {
         log.info("Launching the Burp with options: {}", Arrays.toString(args.getSourceArgs()));
         burp.StartBurp.main(args.getSourceArgs());
      }
      scans = new ScanQueueMap();
   }

   public String getConfigAsJson() {
      log.info("Retrieving the Burp Configuration...");
      return BurpExtender.getInstance().getCallbacks().saveConfigAsJson();
   }

   public void updateConfigFromJson(String configJson) {
      log.info("Updating the Burp Configuration...");
      BurpExtender.getInstance().getCallbacks().loadConfigFromJson(configJson);
   }

   public Config getConfig() {
      Map<String, String> configMap = BurpExtender.getInstance().getCallbacks().saveConfig();

      List<ConfigItem> configItems = new ArrayList<>();
      for (String property : configMap.keySet()) {
         ConfigItem configItem = new ConfigItem(property, configMap.get(property));
         configItems.add(configItem);
      }
      return new Config(configItems);
   }

   public void setConfig(Config config) {
      log.info("Setting the Burp Configuration");
      Map<String, String> configMap = Utils.convertConfigurationListToMap(config);
      BurpExtender.getInstance().getCallbacks().loadConfig(configMap);
   }

   public void updateConfig(Config config) {
      Map<String, String> existingConfiguration = BurpExtender.getInstance().getCallbacks()
            .saveConfig();
      existingConfiguration.putAll(Utils.convertConfigurationListToMap(config));
      log.info("Updating the Burp Configuration");
      BurpExtender.getInstance().getCallbacks().loadConfig(existingConfiguration);
   }

   public List<HttpMessage> getProxyHistory() {
      List<HttpMessage> httpMessageList = new ArrayList<>();
      for (IHttpRequestResponse iHttpRequestResponse : BurpExtender.getInstance().getCallbacks()
            .getProxyHistory()) {
         httpMessageList.add(new HttpMessage(iHttpRequestResponse));
      }
      return httpMessageList;
   }

   public boolean scan(String baseUrl)
         throws MalformedURLException {
      boolean inScope = isInScope(baseUrl);
      log.info("Total SiteMap size: {}", BurpExtender.getInstance().getCallbacks().getSiteMap("").length);
      log.info("Is {} in Scope: {}", baseUrl, inScope);
      if (inScope) {
         IHttpRequestResponse[] siteMapInScope = BurpExtender.getInstance().getCallbacks().getSiteMap(baseUrl);
         log.info("Number of URLs submitting for Active Scan: {}", siteMapInScope.length);
         for (IHttpRequestResponse iHttpRequestResponse : siteMapInScope) {
            URL url = BurpExtender.getInstance().getHelpers().analyzeRequest(iHttpRequestResponse)
                  .getUrl();
            if (url.toExternalForm().startsWith(baseUrl)) {
               boolean useHttps = url.getProtocol().equalsIgnoreCase("HTTPS");
               log.debug("Submitting Active Scan for the URL {}", url.toExternalForm());
               IScanQueueItem iScanQueueItem = BurpExtender.getInstance().getCallbacks()
                     .doActiveScan(url.getHost(), url.getPort(), useHttps,
                           iHttpRequestResponse.getRequest());
               scans.addItem(url.toExternalForm(), iScanQueueItem);
            }
         }
         return true;
      } else {
         log.info("No Scan is performed as the {} URL is not in scope.", baseUrl);
         return false;
      }
   }

   public void clearScans() {
      scans.clear();
   }

   public List<HttpMessage> getSiteMap(String urlPrefix) {
      List<HttpMessage> httpMessageList = new ArrayList<>();
      for (IHttpRequestResponse iHttpRequestResponse : BurpExtender.getInstance().getCallbacks()
            .getSiteMap(urlPrefix)) {
         httpMessageList.add(new HttpMessage(iHttpRequestResponse));
      }
      return httpMessageList;
   }

   // urlString should be encoded for the correct matching.
   public boolean isInScope(String urlString) throws MalformedURLException {
      URL url = new URL(urlString);
      return BurpExtender.getInstance().getCallbacks().isInScope(url);
   }

   // urlString should be encoded for the correct matching.
   public void includeInScope(String urlString) throws MalformedURLException {
      URL url = new URL(urlString);
      BurpExtender.getInstance().getCallbacks().includeInScope(url);
   }

   // urlString should be encoded for the correct matching.
   public void excludeFromScope(String urlString) throws MalformedURLException {
      URL url = new URL(urlString);
      BurpExtender.getInstance().getCallbacks().excludeFromScope(url);

   }

   public List<ScanIssue> getIssues(String urlPrefix) {
      List<ScanIssue> scanIssues = new ArrayList<>();
      IScanIssue[] iScanIssues = BurpExtender.getInstance().getCallbacks()
            .getScanIssues(urlPrefix);
      for (IScanIssue iScanIssue : iScanIssues) {
         scanIssues.add(new ScanIssue(iScanIssue));
      }
      return scanIssues;
   }

   public byte[] generateScanReport(String urlPrefix, ReportType reportType) throws IOException {
      Path reportFile = Files.createTempFile("Report", "." + reportType.getReportType());
      reportFile.toFile().deleteOnExit();
      BurpExtender.getInstance().getCallbacks()
            .generateScanReport(reportType.getReportType(),
                  BurpExtender.getInstance().getCallbacks().getScanIssues(urlPrefix),
                  reportFile.toFile());
      return Files.readAllBytes(reportFile);
   }

   public int getPercentageComplete() {
      log.info("Getting percentage complete.");
      return scans.getPercentageComplete();
   }

   public void sendToSpider(String baseUrl) throws MalformedURLException {
      URL url = new URL(baseUrl);
      BurpExtender.getInstance().getCallbacks().sendToSpider(url);
   }

   public void restoreState(File state) {
      log.info("Restoring state by replacing state with a new state");
      BurpExtender.getInstance().getCallbacks().restoreState(state);
   }

   public void exitSuite(boolean promptUser) {
      log.info("Shutting down the Burp Suite...");
      if (awtHeadLessMode && promptUser) {
         log.info("Burp suite is running in headless mode. Overriding the promptUser to false.");
         promptUser = false;
      }
      BurpExtender.getInstance().getCallbacks().exitSuite(promptUser);
   }

}
