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
import com.vmware.burp.extension.domain.HttpMessage;
import com.vmware.burp.extension.domain.ReportType;
import com.vmware.burp.extension.domain.ScanIssue;
import com.vmware.burp.extension.domain.internal.ScanQueueMap;
import com.vmware.burp.extension.domain.internal.SpiderQueueMap;
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
import java.util.stream.Stream;

@Service
public class BurpService {
    private static final Logger log = LoggerFactory.getLogger(BurpService.class);
    private static final String PROJECT_FILE = "project-file";
    private static final String PROJECT_FILE_ARGUMENT = "--" + PROJECT_FILE + "=";
    private static final String CONFIG_FILE = "config-file";
    private static final String CONFIG_FILE_ARGUMENT = "--" + CONFIG_FILE + "=";
    private static final String USER_CONFIG_FILE = "user-config-file";
    private static final String USER_CONFIG_FILE_ARGUMENT = "--" + USER_CONFIG_FILE + "=";
    private static final String TEMPORARY_PROJECT_FILE_NAME = "temp-project.burp";
    private ScanQueueMap scans;
    private SpiderQueueMap spiders;

    @Value("${java.awt.headless}")
    private boolean awtHeadLessMode;

    @Value("${build.version}")
    private String version;

    @Autowired
    public BurpService(ApplicationArguments args, @Value("${headless.mode}") boolean headlessMode)
            throws IOException {
        if (!headlessMode) {
            log.info("Setting java.awt.headless to false...");
            System.setProperty("java.awt.headless", Boolean.toString(false));
        }
        log.info("# of command line arguments received to Burp suite: {}", args.getSourceArgs().length);
        log.info("Launching Burp suite in {} mode...", headlessMode ? "headless" : "UI");

        String[] projectData;
        String[] projectOptions;
        String[] userOptions;

        //Project Data File
        if (!args.containsOption(PROJECT_FILE)) {
            projectData = new String[]{generateProjectDataTempFile()};
        } else {
            projectData = args.getOptionValues(PROJECT_FILE).stream().toArray(String[]::new);
            for( int i = 0; i < projectData.length; i++) {
                projectData[i] = PROJECT_FILE_ARGUMENT + projectData[i];
            }
        }

        //Project Options File
        if (!args.containsOption(CONFIG_FILE)) {
            projectOptions = new String[]{generateProjectOptionsTempFile()};
        } else {
            projectOptions = args.getOptionValues(CONFIG_FILE).stream().toArray(String[]::new);
            for( int i = 0; i < projectOptions.length; i++) {
                projectOptions[i] = CONFIG_FILE_ARGUMENT + projectOptions[i];
            }
        }

        //User Options File
        if (!args.containsOption(USER_CONFIG_FILE)) {
            userOptions = new String[]{generateUserOptionsTempFile()};
        } else {
            userOptions = args.getOptionValues(USER_CONFIG_FILE).stream().toArray(String[]::new);
            for( int i = 0; i < userOptions.length; i++) {
                userOptions[i] = USER_CONFIG_FILE_ARGUMENT + userOptions[i];
            }
        }

        String[] burpOptions = Stream.concat(Arrays.stream(projectData), Arrays.stream(projectOptions)).toArray(String[]::new);
        burpOptions = Stream.concat(Arrays.stream(burpOptions), Arrays.stream(userOptions)).toArray(String[]::new);

        log.info("Launching the Burp with options: {}", Arrays.toString(burpOptions));
        burp.StartBurp.main(burpOptions);

        scans = new ScanQueueMap();
        spiders = new SpiderQueueMap(3000);
    }

    private String generateProjectOptionsTempFile() throws IOException {
        //Use temporary project configuration file
        Resource defaultProjectOptionsFile = new ClassPathResource("/static/burp-default-project-options.json");
        Path projectOptionsTempFile = Files.createTempFile("project-options", ".json");
        FileCopyUtils
                .copy(FileCopyUtils.copyToByteArray(defaultProjectOptionsFile.getInputStream()),
                        projectOptionsTempFile.toFile());
        projectOptionsTempFile.toFile().deleteOnExit();
        return CONFIG_FILE_ARGUMENT + projectOptionsTempFile.toAbsolutePath();
    }

    private String generateUserOptionsTempFile() throws IOException {
        //Use temporary user configuration file
        Resource defaultUserOptionsFile = new ClassPathResource("/static/burp-default-user-options.json");
        Path userOptionsTempFile = Files.createTempFile("user-options", ".json");
        FileCopyUtils
                .copy(FileCopyUtils.copyToByteArray(defaultUserOptionsFile.getInputStream()),
                        userOptionsTempFile.toFile());
        userOptionsTempFile.toFile().deleteOnExit();
        return USER_CONFIG_FILE_ARGUMENT + userOptionsTempFile.toAbsolutePath();
    }

    private String generateProjectDataTempFile() throws IOException {
        // As of Burp 1.7.03 version, --project-file option is mandatory to launch the jar in CI/CD pipeline.
        // --config-file option is optional

        //Use temporary project data file
        Path projectTempDir = Files.createTempDirectory("temp-project-dir-");
        projectTempDir.toFile().deleteOnExit();
        File file = new File(TEMPORARY_PROJECT_FILE_NAME);
        file.deleteOnExit();
        return PROJECT_FILE_ARGUMENT + projectTempDir.toAbsolutePath() + File.separator + TEMPORARY_PROJECT_FILE_NAME;
    }

    public String getConfigAsJson() {
        log.info("Retrieving the Burp Configuration...");
        return BurpExtender.getInstance().getCallbacks().saveConfigAsJson();
    }

    public String getBurpVersion() {
        log.info("Retrieving the Burp Version...");
        return String.join(".", BurpExtender.getInstance().getCallbacks().getBurpVersion());
    }

    public String getVersion() {
        log.info("Retrieving the burp-rest-api Extension Version...");
        return version;
    }

    public void updateConfigFromJson(String configJson) {
        log.info("Updating the Burp Configuration...");
        BurpExtender.getInstance().getCallbacks().loadConfigFromJson(configJson);
    }

    public List<HttpMessage> getProxyHistory() {
        List<HttpMessage> httpMessageList = new ArrayList<>();
        for (IHttpRequestResponse iHttpRequestResponse : BurpExtender.getInstance().getCallbacks()
                .getProxyHistory()) {
            httpMessageList.add(new HttpMessage(iHttpRequestResponse));
        }
        return httpMessageList;
    }

    public boolean scan(String baseUrl, boolean isActive)
            throws MalformedURLException {
        boolean inScope = isInScope(baseUrl);
        log.info("Total SiteMap size: {}", BurpExtender.getInstance().getCallbacks().getSiteMap("").length);
        log.info("Is {} in Scope: {}", baseUrl, inScope);
        if (inScope) {
            IHttpRequestResponse[] siteMapInScope = BurpExtender.getInstance().getCallbacks().getSiteMap(baseUrl);
            log.info("Number of URLs submitting for Active/Passive Scan: {}", siteMapInScope.length);
            for (IHttpRequestResponse iHttpRequestResponse : siteMapInScope) {
                URL url = BurpExtender.getInstance().getHelpers().analyzeRequest(iHttpRequestResponse)
                        .getUrl();
                if(url.getPort() == url.getDefaultPort()) {
                    url = new URL(url.getProtocol(), url.getHost(), url.getFile());
                }
                // check if the url from the sitemap is still in scope (checking exceptions to scope)
                if(isInScope(url.toExternalForm())){
                    boolean useHttps = url.getProtocol().equalsIgnoreCase("HTTPS");
                    if(isActive) {
                        //Trigger Burp's Active Scan
                        log.debug("Submitting Active Scan for the URL {}", url.toExternalForm());
                        IScanQueueItem iScanQueueItem = BurpExtender.getInstance().getCallbacks()
                                .doActiveScan(url.getHost(), url.getPort() != -1 ? url.getPort() : url.getDefaultPort(), useHttps,
                                        iHttpRequestResponse.getRequest());
                        scans.addItem(url.toExternalForm(), iScanQueueItem);
                    }else{
                        //Trigger Burp's Passive Scan
                        log.debug("Submitting Passive Scan for the URL {}", url.toExternalForm());
                        if (iHttpRequestResponse.getResponse() != null) {
                            BurpExtender.getInstance().getCallbacks()
                                    .doPassiveScan(url.getHost(), url.getPort() != -1 ? url.getPort() : url.getDefaultPort(), useHttps,
                                            iHttpRequestResponse.getRequest(), iHttpRequestResponse.getResponse());
                        }
                    }
                } else {
                    log.info("URL {} not submitted to scan, since it matches a scope exception", url.toExternalForm());
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

    public int getScanPercentageComplete() {
        log.info("Getting Scanner percentage complete.");
        return scans.getPercentageComplete();
    }

    public int getSpiderPercentageComplete() {
        log.info("Estimate Spider percentage complete.");
        return spiders.getPercentageComplete();
    }

    public void sendToSpider(String baseUrl) throws MalformedURLException {
        URL url = new URL(baseUrl);
        BurpExtender.getInstance().getCallbacks().sendToSpider(url);
        spiders.addItem(url.toString(),BurpExtender.getInstance().getCallbacks().getSiteMap(url.toString()));
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

