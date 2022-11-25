/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.service;

import burp.*;
import burp.ICookie;

import com.vmware.burp.extension.domain.Cookie;
import com.vmware.burp.extension.domain.CookieInCookieJar;
import com.vmware.burp.extension.domain.HttpMessage;
import com.vmware.burp.extension.domain.IssueConfidence;
import com.vmware.burp.extension.domain.IssueSeverity;
import com.vmware.burp.extension.domain.ReportType;
import com.vmware.burp.extension.domain.ScanIssue;
import com.vmware.burp.extension.domain.ScanStatus;
import com.vmware.burp.extension.domain.internal.ScanQueueMap;
import com.vmware.burp.extension.domain.internal.SpiderQueueMap;
import com.vmware.burp.extension.utils.UserConfigUtils;
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

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.CookieStore;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.NoRouteToHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
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
    private String restApiPath;
    private final String API_KEY_ARGUMENT = "apikey";
    private String apiKey;

    @Value("${java.awt.headless}")
    private boolean awtHeadLessMode;

    @Value("${build.version}")
    private String version;

    @Autowired
    public BurpService(ApplicationArguments args,
                       @Value("${headless.mode}") boolean headlessMode,
                       @Value("${burp.jar:#{null}}") String burpJar,
                       @Value("${burp.ext:#{null}}") String burpExtension)
            throws IOException, ClassNotFoundException, NoSuchMethodException,
            InvocationTargetException, IllegalAccessException, URISyntaxException {
        if (!headlessMode) {
            log.info("Setting java.awt.headless to false...");
            System.setProperty("java.awt.headless", Boolean.toString(false));
        }
        log.info("# of command line arguments received to Burp suite: {}", args.getSourceArgs().length);
        log.info("Launching Burp suite in {} mode...", headlessMode ? "headless" : "UI");

        String[] projectData;
        String[] projectOptions;
        String[] userOptions;

        UserConfigUtils ucu = new UserConfigUtils();

        //Include the REST API Plugin User Options config
        restApiPath = extractPlugin();
        ucu.registerBurpExtension(restApiPath);

        if (burpExtension != null) {
            log.info("Loading extensions {}", burpExtension);
            for (String extension : burpExtension.split(",")) {
                ucu.registerBurpExtension(Paths.get(extension).toAbsolutePath().normalize().toString());
            }
        }

        //Project Data File
        if (!args.containsOption(PROJECT_FILE)) {
            projectData = new String[]{generateProjectDataTempFile()};
        } else {
            projectData = args.getOptionValues(PROJECT_FILE).stream().toArray(String[]::new);
            for(int i = 0; i < projectData.length; i++) {
                projectData[i] = PROJECT_FILE_ARGUMENT + projectData[i];
            }
        }

        //Project Options File
        if (!args.containsOption(CONFIG_FILE)) {
            projectOptions = new String[]{generateProjectOptionsTempFile()};
        } else {
            projectOptions = args.getOptionValues(CONFIG_FILE).stream().toArray(String[]::new);
            for(int i = 0; i < projectOptions.length; i++) {
                projectOptions[i] = CONFIG_FILE_ARGUMENT + projectOptions[i];
            }
        }

        //User Options File
        if (!args.containsOption(USER_CONFIG_FILE)) {
            userOptions = new String[]{USER_CONFIG_FILE_ARGUMENT + ucu.injectExtensions(generateUserOptionsTempFile())};
        } else {
            userOptions = args.getOptionValues(USER_CONFIG_FILE).stream().toArray(String[]::new);
            for(int i = 0; i < userOptions.length; i++) {
                userOptions[i] = USER_CONFIG_FILE_ARGUMENT + ucu.injectExtensions(userOptions[i]);
            }
        }

        // apikey argument parsing, if present
        if (args.containsOption(API_KEY_ARGUMENT)) {
            String[] apiKeysValues = args.getOptionValues(API_KEY_ARGUMENT).stream().toArray(String[]::new);
            setAPIKey(apiKeysValues);
        }


        String[] burpOptions = Stream.concat(Arrays.stream(projectData), Arrays.stream(projectOptions)).toArray(String[]::new);
        burpOptions = Stream.of(
                Arrays.stream(args.getSourceArgs()).filter(arg -> !arg.contains(API_KEY_ARGUMENT)),
                Arrays.stream(burpOptions),
                Arrays.stream(userOptions))
                .reduce(Stream::concat).orElseGet(Stream::empty).toArray(String[]::new);

        log.info("Launching the Burp with options: {}", Arrays.toString(burpOptions));
        if (burpJar != null) {
            log.info("Injecting ClassLoader with Jar: {}", burpJar);
            URL url = new File(burpJar).toURI().toURL();
            injectClassLoader(url);
        }
        BurpService.class.getClassLoader().loadClass("burp.StartBurp")
                .getMethod("main", String[].class)
                .invoke(null, (Object)burpOptions);

        scans = new ScanQueueMap();
        spiders = new SpiderQueueMap(3000);
    }

    private void setAPIKey(String[] apiKeysValues) {
        if (apiKeysValues.length == 1 && apiKeysValues[0].trim().length() > 0) {
            log.info("APIKEY received");
            this.apiKey = apiKeysValues[0];
        }
        else {
            log.warn("APIKEY has empty value");
        }
    }

    public String getAPIKey() {
        return this.apiKey;
    }

    // TODO: This call will fail on Java > 1.8 .
    // Find a solution in the future.
    private static void injectClassLoader(URL url)
            throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        URLClassLoader loader = (URLClassLoader)ClassLoader.getSystemClassLoader();
        Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[]{URL.class});
        method.setAccessible(true);
        method.invoke(loader, new Object[]{ url });
    }

    private String extractPlugin() throws IOException {
        //Use temporary rest-api.jar plugin
        Resource restApiFile = new ClassPathResource("/static/rest-api.jar");
        Path restApiTempFile = Files.createTempFile("rest-api_", ".jar");
        FileCopyUtils
                .copy(FileCopyUtils.copyToByteArray(restApiFile.getInputStream()),
                        restApiTempFile.toFile());
        restApiTempFile.toFile().deleteOnExit();
        return restApiTempFile.toAbsolutePath().toString();
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
        return  userOptionsTempFile.toAbsolutePath().toString();
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

    public String getConfigAsJson(String configPaths) {
        if (configPaths != null) {
            log.info("Retrieving the Burp Configuration for configPaths: " + configPaths);
            return LegacyBurpExtender.getInstance().getCallbacks().saveConfigAsJson(configPaths);
        } else {
            log.info("Retrieving the Burp Configuration with empty configPaths");
            return LegacyBurpExtender.getInstance().getCallbacks().saveConfigAsJson();
        }
    }

    public String getBurpVersion() {
        log.info("Retrieving the Burp Version...");
        return String.join(".", LegacyBurpExtender.getInstance().getCallbacks().getBurpVersion());
    }

    public String getVersion() {
        log.info("Retrieving the burp-rest-api Extension Version...");
        return version;
    }

    public void updateConfigFromJson(String configJson) {
        log.info("Updating the Burp Configuration...");
        LegacyBurpExtender.getInstance().getCallbacks().loadConfigFromJson(configJson);
    }

    public List<HttpMessage> getProxyHistory() throws UnsupportedEncodingException {
        List<HttpMessage> httpMessageList = new ArrayList<>();
        for (IHttpRequestResponse iHttpRequestResponse : LegacyBurpExtender.getInstance().getCallbacks()
                .getProxyHistory()) {
            httpMessageList.add(new HttpMessage(iHttpRequestResponse));
        }
        return httpMessageList;
    }

    private boolean isValidInsertionPoint(List<int[]> input) {
        return input != null &&
                input.size() > 0 &&
                input.stream().allMatch(i -> i.length == 2 && i[0] < i[1]);
    }

    public boolean scan(String baseUrl, boolean isActive) throws MalformedURLException, NoRouteToHostException, URISyntaxException {
        return this.scan(baseUrl, isActive, null);
    }

    public boolean scan(String baseUrl, boolean isActive, List<int[]> insertionPoints)
            throws MalformedURLException, NoRouteToHostException, URISyntaxException {
        boolean inScope = isInScope(baseUrl);
        log.info("Total SiteMap size: {}", LegacyBurpExtender.getInstance().getCallbacks().getSiteMap("").length);
        log.info("Is {} in Scope: {}", baseUrl, inScope);
        if (inScope) {
            // check if the target is reachable and include the base IHttpRequestResponse in the sitemap
            URL target = new URL(baseUrl);
            boolean isHttps = target.getProtocol().equalsIgnoreCase("HTTPS");
            int targetPort = target.getPort() != -1 ? target.getPort() : (isHttps ? 443 : 80);
            IHttpService reqHttpService = LegacyBurpExtender.getInstance().getHelpers().buildHttpService(target.getHost(), targetPort, isHttps);
            IHttpRequestResponse reqResHttpService = null;
            try {
                reqResHttpService = LegacyBurpExtender.getInstance().getCallbacks().makeHttpRequest(reqHttpService, LegacyBurpExtender.getInstance().getHelpers().buildHttpRequest(target));
            }catch(RuntimeException runtimeException){
                log.info("Active Scan Target Connection Error. A Fatal Error Occurred!");
                throw new NoRouteToHostException("Active Scan Target Connection Error");
            }
            if (reqResHttpService.getResponse() == null || (reqResHttpService.getResponse() != null && reqResHttpService.getResponse().length == 0)){
                log.info("Active Scan Target Did Not Respond. A Fatal Error Occurred!");
                throw new NoRouteToHostException("Active Scan Target Did Not Respond");
            }
            LegacyBurpExtender.getInstance().getCallbacks().addToSiteMap(reqResHttpService);
            IHttpRequestResponse[] siteMapInScope = Utils.getSiteMapWrapper(baseUrl);
            log.info("Number of URLs submitting for Active/Passive Scan: {}", siteMapInScope.length);
            for (IHttpRequestResponse iHttpRequestResponse : siteMapInScope) {
                URL url = LegacyBurpExtender.getInstance().getHelpers().analyzeRequest(iHttpRequestResponse)
                        .getUrl();
                if(url.getPort() == url.getDefaultPort()) {
                    url = new URL(url.getProtocol(), url.getHost(), url.getFile());
                }
                // check if the url from the sitemap is still in scope (checking exceptions to scope)
                if(isInScope(url.toExternalForm())){
                    if (iHttpRequestResponse.getResponse() == null) {
                        // Do not scan site map entries without a response
                        continue;
                    }
                    boolean useHttps = url.getProtocol().equalsIgnoreCase("HTTPS");
                    if(isActive) {
                        //Trigger Burp's Active Scan
                        IScanQueueItem iScanQueueItem;
                        if (isValidInsertionPoint(insertionPoints)) {
                            log.debug("Submitting Active Scan for the URL {} with insertion points",
                                    url.toExternalForm());
                            iScanQueueItem = LegacyBurpExtender.getInstance().getCallbacks()
                                    .doActiveScan(url.getHost(),
                                            url.getPort() != -1 ? url.getPort() : url.getDefaultPort(), useHttps,
                                            iHttpRequestResponse.getRequest(), insertionPoints);
                        } else {
                            log.debug("Submitting Active Scan for the URL {}", url.toExternalForm());
                            iScanQueueItem = LegacyBurpExtender.getInstance().getCallbacks()
                                    .doActiveScan(url.getHost(),
                                            url.getPort() != -1 ? url.getPort() : url.getDefaultPort(), useHttps,
                                            iHttpRequestResponse.getRequest());
                        }
                        scans.addItem(url.toExternalForm(), iScanQueueItem);
                    }else{
                        //Trigger Burp's Passive Scan
                        log.debug("Submitting Passive Scan for the URL {}", url.toExternalForm());
                        LegacyBurpExtender.getInstance().getCallbacks()
                                .doPassiveScan(url.getHost(), url.getPort() != -1 ? url.getPort() : url.getDefaultPort(), useHttps,
                                        iHttpRequestResponse.getRequest(), iHttpRequestResponse.getResponse());
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

    public List<HttpMessage> getSiteMap(String urlPrefix) throws UnsupportedEncodingException, MalformedURLException {
        List<HttpMessage> httpMessageList = new ArrayList<>();
        for (IHttpRequestResponse iHttpRequestResponse : Utils.getSiteMapWrapper(urlPrefix)) {
            httpMessageList.add(new HttpMessage(iHttpRequestResponse));
        }
        return httpMessageList;
    }

    // urlString should be encoded for the correct matching.
    public boolean isInScope(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        return LegacyBurpExtender.getInstance().getCallbacks().isInScope(url);
    }

    // urlString should be encoded for the correct matching.
    public void includeInScope(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        LegacyBurpExtender.getInstance().getCallbacks().includeInScope(url);
    }

    // urlString should be encoded for the correct matching.
    public void excludeFromScope(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        LegacyBurpExtender.getInstance().getCallbacks().excludeFromScope(url);

    }

    public List<ScanIssue> getIssues(String urlPrefix) throws UnsupportedEncodingException {
        List<ScanIssue> scanIssues = new ArrayList<>();
        IScanIssue[] iScanIssues = LegacyBurpExtender.getInstance().getCallbacks()
                .getScanIssues(urlPrefix);
        for (IScanIssue iScanIssue : iScanIssues) {
            scanIssues.add(new ScanIssue(iScanIssue));
        }
        return scanIssues;
    }

    public byte[] generateScanReport(String[] urlPrefixes, ReportType reportType, IssueSeverity[] issueSeverities,
                                     IssueConfidence[] issueConfidences) throws IOException {
        Path reportFile = Files.createTempFile("Report", "." + reportType.getReportType());
        reportFile.toFile().deleteOnExit();

        IBurpExtenderCallbacks burpExtenderCallbacks = LegacyBurpExtender.getInstance().getCallbacks();

        Supplier<Stream<IScanIssue>> scanIssuesSupplier = () ->
                Arrays.stream(burpExtenderCallbacks.getScanIssues(null));

        boolean shouldFilterBySeverity = issueSeverities.length > 0 && !Arrays.asList(issueSeverities).contains(IssueSeverity.All);
        boolean shouldFilterByConfidence = issueConfidences.length > 0 && !Arrays.asList(issueConfidences).contains(IssueConfidence.All);

        Supplier<Stream<String>> urlPrefixesSupplier = () -> Arrays.stream(urlPrefixes);
        List<String> severities = Arrays.stream(issueSeverities)
                .map(issueSeverity -> issueSeverity.getIssueSeverity())
                .collect(Collectors.toList());
        List<String> confidences = Arrays.stream(issueConfidences)
                .map(issueConfidence -> issueConfidence.getIssueConfidence())
                .collect(Collectors.toList());

        IScanIssue[] filteredScanIssues = scanIssuesSupplier.get()
                .filter(scanIssue ->
                        // Filter by url prefix.
                        urlPrefixesSupplier.get().anyMatch(urlPrefix ->
                                scanIssue.getUrl().getPort() == 80 || scanIssue.getUrl().getPort() == 443
                                    ? Utils.convertURLToStringWithoutPort(scanIssue.getUrl()).startsWith(urlPrefix)
                                    : scanIssue.getUrl().toString().startsWith(urlPrefix))
                        // Filter by severity.
                        && (!shouldFilterBySeverity || severities.contains(scanIssue.getSeverity()))
                        // Filter by confidence.
                        && (!shouldFilterByConfidence || confidences.contains(scanIssue.getConfidence())))
                .toArray(IScanIssue[]::new);

        burpExtenderCallbacks.generateScanReport(reportType.getReportType(),
                filteredScanIssues,
                reportFile.toFile());

        return Files.readAllBytes(reportFile);
    }

    public List<ScanStatus> getScanStatuses() {
        log.info("Retrieving Scans statuses.");
        return scans.getScanStatuses().stream()
                .map(status -> new ScanStatus(status[0], status[1]))
                .collect(Collectors.toList());
    }


    public int getScannerPercentageComplete() {
        log.info("Getting scanner percentage of completion");
        return scans.getPercentageComplete();
    }

    public int getSpiderPercentageComplete() throws MalformedURLException {
        log.info("Estimate Spider percentage complete.");
        return spiders.getPercentageComplete();
    }

    public void sendToSpider(String baseUrl) throws MalformedURLException {
        URL url = new URL(baseUrl);
        LegacyBurpExtender.getInstance().getCallbacks().sendToSpider(url);
        spiders.addItem(url.toString(),Utils.getSiteMapWrapper(baseUrl));
    }

    public List<ICookie> getCookieFromCookieJar() {
        List<ICookie> cookieJarContents = LegacyBurpExtender.getInstance().getCallbacks().getCookieJarContents();
        return cookieJarContents;
    }

    public void updateCookieInCookieJar(List<CookieInCookieJar> toUpdate) {
        for (ICookie c : toUpdate) {
            log.info("Desired update for Cookie" + c.getName() + " - " + c.getValue());
            LegacyBurpExtender.getInstance().getCallbacks().updateCookieJar(c);
        }
    }

    public void exitSuite(boolean promptUser) {
        log.info("Shutting down the Burp Suite...");
        if (awtHeadLessMode && promptUser) {
            log.info("Burp suite is running in headless mode. Overriding the promptUser to false.");
            promptUser = false;
        }
        try {
            // When Burp finds old temporary projects it ask whether to delete or to keep them. If you call the endopoint /burp/stop 
            // in that case, the burpExtension is not registered yet and it throws the NullPointerException.
            LegacyBurpExtender.getInstance().getCallbacks().exitSuite(promptUser);
        } catch (Exception e) {
            log.info("Burp encountered an exception while stopping. Shutdown in progress");
            e.printStackTrace();
            System.exit(-1); 
        }
    }
}

