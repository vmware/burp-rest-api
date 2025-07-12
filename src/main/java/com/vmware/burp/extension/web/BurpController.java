/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vmware.burp.extension.domain.ScanStatusList;
import com.vmware.burp.extension.domain.*;
import com.vmware.burp.extension.service.BurpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.NoRouteToHostException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import burp.ICookie;

import static org.springframework.web.bind.annotation.RequestMethod.*;

@RestController
@RequestMapping("/burp")
public class BurpController {
   private static final Logger log = LoggerFactory.getLogger(BurpController.class);

   @Autowired
   private BurpService burp;

   public BurpController() {
   }

   @Operation(summary = "Get the version of Burp and the version of the burp-rest-api Extension", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
           @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = Versions.class))),
           @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/versions")
   public Versions getVersions() {
      Versions runningVersions = new Versions();
      runningVersions.setBurpVersion(burp.getBurpVersion());
      runningVersions.setExtensionVersion(burp.getVersion());
      return runningVersions;
   }

   @Operation(summary = "Get Burp suite project-level configuration", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
           @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = JsonNode.class))),
           @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/configuration")
   public JsonNode getConfiguration() throws IOException {
      String configuration = burp.getConfigAsJson("");
      return new ObjectMapper().readTree(configuration);
   }

   @Operation(summary = "Get Burp suite project-level configuration with provided configuration path", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
           @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = JsonNode.class))),
           @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = POST, value = "/configuration")
   public JsonNode getConfiguration(@RequestBody String configAsJson) throws IOException {
      String configuration = burp.getConfigAsJson(configAsJson);
      return new ObjectMapper().readTree(configuration);
   }

   @Operation(summary = "Update Burp suite project-level configuration", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "configAsJson", description = "Configuration as Json String", required = true, schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = JsonNode.class))),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = PUT, value = "/configuration")
   public void updateConfiguration(@RequestBody String configAsJson) {
      if (configAsJson == null) {
         throw new IllegalArgumentException("Required: Configuration in request body.");
      }
      burp.updateConfigFromJson(configAsJson);
   }

   @Operation(summary = "Get Burp suite Proxy History", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = HttpMessageList.class))),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/proxy/history")
   public HttpMessageList getProxyHistory() throws UnsupportedEncodingException {
      HttpMessageList httpMessageList = new HttpMessageList();
      httpMessageList.setHttpMessages(burp.getProxyHistory());
      return httpMessageList;
   }


   @Operation(summary = "Get Burp suite Proxy Partial History", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
      @Parameter(name = "from", description = "Position of the starting request - starting from 1", required = true, schema = @Schema(type = "string")),
      @Parameter(name = "to", description = "Position of the last desired request. If not set, return history to the last request", required = false, schema = @Schema(type = "string"))
})
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = HttpMessageList.class))),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/proxy/history/partial")
   public HttpMessageList getProxyPartialHistory(@RequestParam String from, @RequestParam(required = false) String to) throws UnsupportedEncodingException {
      List<HttpMessage> history = burp.getProxyHistory();
      if (history.isEmpty()) {
         throw new IllegalArgumentException("History proxy is empty");
      }

      if (StringUtils.isEmpty(from)) {
         throw new IllegalArgumentException("The 'from' parameter must not be null or empty.");
      }
      int fromIndex = Integer.parseInt(from);
      int toIndex =  -1;
      if (fromIndex < 1) {
         throw new IllegalArgumentException("The 'from' parameter must start from 1");
      }
      if (!StringUtils.isEmpty(to)) {
         toIndex = Integer.parseInt(to);
      }
      else {
         toIndex = history.size();
      }

      if (fromIndex > history.size() || toIndex > history.size()) {
         throw new IllegalArgumentException("Indexes out of bound: Min value for 'from' : " + 1 + " - Max value for 'to': " +history.size());
      }

      List<HttpMessage> sublistHistory = history.subList(fromIndex -1, toIndex);
      HttpMessageList httpMessageList = new HttpMessageList();
      httpMessageList.setHttpMessages(sublistHistory);
      return httpMessageList;
   }

   @Operation(summary = "Get Burp suite Site Map", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "urlPrefix", description = "URL prefix in order to extract a specific subset of the site map. Performs a simple case-sensitive text match, returning all site map items whose URL begins with the specified prefix. Returns entire site map if this parameter is null.", schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = HttpMessageList.class))),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/target/sitemap")
   public HttpMessageList getSiteMap(@RequestParam(required = false) String urlPrefix) throws UnsupportedEncodingException, MalformedURLException {
      HttpMessageList httpMessageList = new HttpMessageList();
      httpMessageList.setHttpMessages(burp.getSiteMap(urlPrefix));
      return httpMessageList;
   }

   @Operation(summary = "Query if an url is in scope", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "url", description = "Url string to check for scope.", required = true, schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = ScopeItem.class))),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/target/scope")
   public ScopeItem isInScope(@RequestParam String url) throws MalformedURLException {
      if (StringUtils.isEmpty(url)) {
         throw new IllegalArgumentException("The 'url' parameter must not be null or empty.");
      }
      ScopeItem scopeItem = new ScopeItem(url, burp.isInScope(url));
      scopeItem.setInScope(burp.isInScope(url));
      return scopeItem;
   }

   @Operation(summary = "Include an Url in scope", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "url", description = "Url string to include in the Suite-wide scope.", required = true, schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success"),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = PUT, value = "/target/scope")
   public void includeInScope(@RequestParam String url)
         throws MalformedURLException {
      if (StringUtils.isEmpty(url)) {
         throw new IllegalArgumentException("The 'url' parameter must not be null or empty.");
      }
      burp.includeInScope(url);
   }

   @Operation(summary = "Exclude an Url from scope", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "url", description = "Url string to exclude from the Suite-wide scope.", required = true, schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success"),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = DELETE, value = "/target/scope")
   public void updateScope(@RequestParam String url)
         throws MalformedURLException {
      if (StringUtils.isEmpty(url)) {
         throw new IllegalArgumentException("The 'url' parameter must not be null or empty.");
      }
      burp.excludeFromScope(url);
   }

   @Operation(summary = "Send a base url to Burp Scanner to perform a passive scan", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
           @Parameter(name = "baseUrl", description = "Base Url to submit for Passive scan.", required = true, schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
           @ApiResponse(responseCode = "200", description = "Success"),
           @ApiResponse(responseCode = "400", description = "Bad Request"),
           @ApiResponse(responseCode = "409", description = "Conflict"),
           @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = POST, value = "/scanner/scans/passive")
   public void scanPassive(@RequestParam(value = "baseUrl") String baseUrl)
           throws MalformedURLException, NoRouteToHostException, URISyntaxException {
      if (StringUtils.isEmpty(baseUrl)) {
         throw new IllegalArgumentException("The 'baseUrl' parameter in payload must not be null or empty.");
      }

      boolean inScope = burp.isInScope(baseUrl);
      log.info("Is {} in Scope: {}", baseUrl, inScope);
      if (!inScope) {
         log.info("Scan is NOT performed as the {} URL is not in scope.", baseUrl);
         throw new IllegalStateException("The 'baseUrl' is NOT in scope. Set the 'baseUrl' scope to true before retry.");
      }

      burp.scan(baseUrl,false);
   }

   @Operation(summary = "Send a base url to Burp Scanner to perform active scan", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "baseUrl", description = "Base Url to submit for Active scan.", required = true, schema = @Schema(type = "string")),
         @Parameter(name = "insertionPoint", description = "List of insertion points for active scan.", required = false, array = @ArraySchema(schema = @Schema(type = "string")))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success"),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "409", description = "Conflict"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = POST, value = "/scanner/scans/active")
   public void scanActive(
           @RequestParam(value = "baseUrl") String baseUrl,
           @RequestParam(value = "insertionPoint", required = false) List<String> insertionPoints
   )
           throws MalformedURLException, NoRouteToHostException, URISyntaxException {
      if (StringUtils.isEmpty(baseUrl)) {
         throw new IllegalArgumentException("The 'baseUrl' parameter in payload must not be null or empty.");
      }
      List<int[]> convertedInsertionPoint = null;
      if (insertionPoints != null && insertionPoints.size() != 0) {
         convertedInsertionPoint = insertionPoints.stream().map(param ->
                 Arrays.stream(param.split(":")).mapToInt(i -> Integer.parseInt(i, 10)).toArray()
         ).collect(Collectors.toList());
      }

      boolean inScope = burp.isInScope(baseUrl);
      log.info("Is {} in Scope: {}", baseUrl, inScope);
      if (!inScope) {
         log.info("Scan is NOT performed as the {} URL is not in scope.", baseUrl);
         throw new IllegalStateException("The 'baseUrl' is NOT in scope. Set the 'baseUrl' scope to true before retry.");
      }

      burp.scan(baseUrl, true, convertedInsertionPoint);
   }

   @Operation(summary = "Deletes the active scan queue map from memory", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = DELETE, value = "/scanner/scans/active")
   public void clearScans() {
      burp.clearScans();
   }

   @Operation(summary = "Get the current scan issues", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "urlPrefix", description = "URL prefix in order to extract a specific subset of scan issues.", schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = ScanIssueList.class))),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/scanner/issues")
   public ScanIssueList getScanIssues(@RequestParam(required = false) String urlPrefix) throws UnsupportedEncodingException {
      ScanIssueList scanIssueList = new ScanIssueList();
      scanIssueList.setScanIssues(burp.getIssues(urlPrefix));
      return scanIssueList;
   }

   @Operation(summary = "Get the scan report with Scanner issues", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "urlPrefix", description = "URL prefix in order to extract and include a specific subset of scan issues in the report. Multiple values are also accepted if they are comma-separated.", schema = @Schema(type = "string")),
         @Parameter(name = "reportType", description = "Format to be used to generate report. Acceptable values are HTML and XML.", schema = @Schema(type = "string")),
         @Parameter(name = "issueSeverity", description = "Severity of the scan issues to be included in the report. Acceptable values are All, High, Medium, Low and Information. Multiple values are also accepted if they are comma-separated.", schema = @Schema(type = "string")),
         @Parameter(name = "issueConfidence", description = "Confidence of the scan issues to be included in the report. Acceptable values are All, Certain, Firm and Tentative. Multiple values are also accepted if they are comma-separated.", schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = Byte[].class))),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/report")
   public byte[] generateReport(@RequestParam String urlPrefix,
                                @RequestParam(required = false, defaultValue = "HTML") String reportType,
                                @RequestParam(required = false, defaultValue = "All") String issueSeverity,
                                @RequestParam(required = false, defaultValue = "All") String issueConfidence)
         throws IOException {

      List<String> urlPrefixes = new ArrayList<>();
      if (urlPrefix != null && !urlPrefix.trim().isEmpty()) {
         urlPrefixes = Arrays.stream(urlPrefix.split(","))
                 .map(String :: trim)
                 .collect(Collectors.toList());
      }

      try {
         ReportType.valueOf(reportType);
      } catch (Exception e) {
         log.error("Invalid Report Type in the request: {}", reportType);
         throw new IllegalArgumentException(
               "Invalid value for the reportType parameter. Valid values: HTML, XML.");
      }

      List<IssueSeverity> issueSeverities = new ArrayList<>();
      try {
         for (String sev : issueSeverity.split(",")) {
            issueSeverities.add(IssueSeverity.valueOf(sev.trim()));
         }
      } catch (Exception e) {
         log.error("Invalid Issue Severity in the request: {}", issueSeverity);
         throw new IllegalArgumentException(
                 "Invalid value for the issueSeverity parameter. Valid values: All, High, Medium, Low, Information.");
      }

      List<IssueConfidence> issueConfidences = new ArrayList<>();
      try {
         for (String conf : issueConfidence.split(",")) {
            issueConfidences.add(IssueConfidence.valueOf(conf.trim()));
         }
      } catch (Exception e) {
         log.error("Invalid Issue Confidence in the request: {}", issueConfidence);
         throw new IllegalArgumentException(
                 "Invalid value for the issueConfidence parameter. Valid values: All, Certain, Firm, Tentative.");
      }

      return burp.generateScanReport(urlPrefixes.toArray(new String[0]), ReportType.valueOf(reportType),
              issueSeverities.toArray(new IssueSeverity[0]), issueConfidences.toArray(new IssueConfidence[0]));
   }

   @Operation(summary = "Get the status of each scan", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = ScanStatusList.class))),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/scanner/status/details")
   public ScanStatusList scanPercentComplete() {
      ScanStatusList scanStatusList = new ScanStatusList();
      scanStatusList.setScanStatuses(burp.getScanStatuses());
      return scanStatusList;
   }

   @Operation(summary = "Get the percentage of the scan completion", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = ScanProgress.class))),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/scanner/status")
   public ScanProgress scanPercentCompletePercentage() {
      int percentageComplete = burp.getScannerPercentageComplete();
      ScanProgress scanProgress = new ScanProgress();
      scanProgress.setTotalScanPercentage(percentageComplete);
      return  scanProgress;
      
   }

    @Operation(summary = "Get the status of the spider", security = @SecurityRequirement(name = "APIKEY"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Success", content = @Content(schema = @Schema(implementation = SpiderProgress.class))),
            @ApiResponse(responseCode = "500", description = "Failure")
    })
    @RequestMapping(method = GET, value = "/spider/status")
    public SpiderProgress spiderPercentComplete() throws MalformedURLException {
        SpiderProgress spiderProgress = new SpiderProgress();
        spiderProgress.setTotalSpiderPercentage(burp.getSpiderPercentageComplete());
        return spiderProgress;
    }

   @Operation(summary = "Get the cookies in the CookieJar", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
           @ApiResponse(responseCode = "200", description = "Success"),
           @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/cookiejar")
   public List<ICookie> getCookiesFromCookieJar() {
      List<ICookie> cookieFromCookieJar = burp.getCookieFromCookieJar();
      return cookieFromCookieJar;
   }

   @Operation(summary = "Update the cookies in the CookieJar", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
           @ApiResponse(responseCode = "200", description = "Success"),
           @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = PUT, value = "/cookiejar")
   public void updateCookiesInCookieJar(@RequestBody List<CookieInCookieJar> cookieJarList) {
      if (cookieJarList == null) {
         throw new IllegalArgumentException("Invalid json received");
      }
      burp.updateCookieInCookieJar(cookieJarList);

   }

   @Operation(summary = "Send a seed url to Burp Spider", security = @SecurityRequirement(name = "APIKEY"))
   @Parameters({
         @Parameter(name = "baseUrl", description = "Base Url to send to Spider tool.", required = true, schema = @Schema(type = "string"))
   })
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success"),
         @ApiResponse(responseCode = "400", description = "Bad Request"),
         @ApiResponse(responseCode = "409", description = "Conflict"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = POST, value = "/spider")
   public void sendToSpider(@RequestParam String baseUrl)
         throws MalformedURLException {
      if (StringUtils.isEmpty(baseUrl)) {
         throw new IllegalArgumentException("The 'baseUrl' parameter in payload must not be null or empty.");
      }

      boolean inScope = burp.isInScope(baseUrl);
      log.info("Is {} in Scope: {}", baseUrl, inScope);
      if (!inScope) {
         log.info("Spider is NOT performed as the {} URL is not in scope.", baseUrl);
         throw new IllegalStateException("The 'baseUrl' is NOT in scope. Set the 'baseUrl' scope to true before retry.");
      }

      burp.sendToSpider(baseUrl);
   }

   @Operation(summary = "Stop Burp Suite", security = @SecurityRequirement(name = "APIKEY"))
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "Success"),
         @ApiResponse(responseCode = "500", description = "Failure")
   })
   @RequestMapping(method = GET, value = "/stop")
   public void exitBurp(){
         burp.exitSuite(false);
         log.info("Burp is stopped");
      }

   @ExceptionHandler()
   void handleIllegalArgumentException(IllegalArgumentException e, HttpServletResponse response) throws IOException {
      response.sendError(HttpStatus.BAD_REQUEST.value(), e.getMessage());
   }

   @ExceptionHandler()
   void handleIllegalStateException(IllegalStateException e, HttpServletResponse response) throws IOException {
      response.sendError(HttpStatus.CONFLICT.value(), e.getMessage());
   }

   @ExceptionHandler()
   void handleMalformedURLException(MalformedURLException e, HttpServletResponse response)
         throws IOException {
      response.sendError(HttpStatus.BAD_REQUEST.value(), e.getMessage());
   }
}
