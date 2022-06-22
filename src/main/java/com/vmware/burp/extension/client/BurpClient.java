/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vmware.burp.extension.domain.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class BurpClient {
   private static final Logger log = LoggerFactory.getLogger(BurpClient.class);
   private RestTemplate restTemplate;
   private String baseUrl;

   public BurpClient(String baseUrl) {
      this(baseUrl, new RestTemplate());
   }

   public BurpClient(String baseUrl, RestTemplate restTemplate) {
      this.baseUrl = baseUrl;
      this.restTemplate = restTemplate;
      List<HttpMessageConverter<?>> converters = new ArrayList<>();
      converters.add(new MappingJackson2HttpMessageConverter());
      converters.add(new ByteArrayHttpMessageConverter());
      restTemplate.setMessageConverters(converters);
   }

   public JsonNode getConfiguration() {
      String uriString = buildUriFromPathSegments("burp", "configuration");
      return restTemplate.getForObject(uriString, JsonNode.class);
   }

   public void updateConfiguration(JsonNode configJson) {
      String uriString = buildUriFromPathSegments("burp", "configuration");
      restTemplate.put(uriString, configJson);
   }

   public Config getConfig() {
      String uriString = buildUriFromPathSegments("burp", "config");
      return restTemplate.getForObject(uriString, Config.class);
   }

   public void setConfig(Config configuration) {
      String uriString = buildUriFromPathSegments("burp", "config");
      restTemplate.postForLocation(uriString, configuration);
   }

   public void updateConfig(Config configuration) {
      String uriString = buildUriFromPathSegments("burp", "config");
      restTemplate.put(uriString, configuration);
   }

   public HttpMessageList getProxyHistory() {
      String uriString = buildUriFromPathSegments("burp", "proxy", "history");
      return restTemplate.getForObject(uriString, HttpMessageList.class);
   }

   public HttpMessageList getPartialProxyHistory(String from, String to) {
      String uriString = buildUriFromPathSegments("burp", "proxy", "history", "partial");
      URI uri = UriComponentsBuilder.fromHttpUrl(uriString).queryParam("from", from).queryParam("to", to).build().toUri();
      return restTemplate.getForObject(uri, HttpMessageList.class);
   }


   public HttpMessageList getSiteMap(String urlPrefix) {
      String uriString = buildUriFromPathSegments("burp", "target", "sitemap");
      if (!StringUtils.isEmpty(urlPrefix)) {
         URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("urlPrefix", urlPrefix)
               .build().toUri();
         return restTemplate.getForObject(uri, HttpMessageList.class);
      }
      return restTemplate.getForObject(uriString, HttpMessageList.class);
   }

   public boolean isInScope(String url) {
      String uriString = buildUriFromPathSegments("burp", "target", "scope");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("url", url).build()
            .toUri();
      ObjectNode response = restTemplate.getForObject(uri, ObjectNode.class);
      return response.get("inScope").asBoolean();
   }

   public void includeInScope(String url) {
      String uriString = buildUriFromPathSegments("burp", "target", "scope");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("url", url).build()
            .toUri();
      restTemplate.put(uri, null);
   }

   public void excludeFromScope(String url) {
      String uriString = buildUriFromPathSegments("burp", "target", "scope");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("url", url).build()
            .toUri();
      restTemplate.delete(uri);
   }

   public void scan(String baseUrl) {
      String uriString = buildUriFromPathSegments("burp", "scanner", "scans", "active");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("baseUrl", baseUrl)
            .build().toUri();
      restTemplate.postForLocation(uri, null);
   }

   //TODO: Client method for clearScans. Is this needed?

   public ScanStatusList getScanStatuses() {
      String uriString = buildUriFromPathSegments("burp", "scanner", "status", "details");
      return restTemplate.getForObject(uriString, ScanStatusList.class);
   }

   public ScanIssueList getScanIssues(String urlPrefix) {
      String uriString = buildUriFromPathSegments("burp", "scanner", "issues");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("urlPrefix", urlPrefix)
            .build().toUri();
      return restTemplate.getForObject(uri, ScanIssueList.class);
   }

   public ScanIssueList getScanIssues() {
      String uriString = buildUriFromPathSegments("burp", "scanner", "issues");
      return restTemplate.getForObject(uriString, ScanIssueList.class);
   }

   public byte[] getReportData(String urlPrefix, ReportType reportType,
                               IssueSeverity[] issueSeverity, IssueConfidence[] issueConfidence) {
      String uriString = buildUriFromPathSegments("burp", "report");
      String issueSeverityStr = null;
      if (issueSeverity != null) {
         issueSeverityStr = String.join(",", Arrays.stream(issueSeverity)
                 .map(severity -> severity.getIssueSeverity())
                 .collect(Collectors.toList()));
      }
      String issueConfidenceStr = null;
      if (issueConfidence != null) {
         issueConfidenceStr = String.join(",", Arrays.stream(issueConfidence)
                 .map(confidence -> confidence.getIssueConfidence())
                 .collect(Collectors.toList()));
      }
      URI uri = UriComponentsBuilder.fromUriString(uriString)
              .queryParam("urlPrefix", urlPrefix)
              .queryParam("reportType", reportType)
              .queryParam("issueSeverity", issueSeverityStr)
              .queryParam("issueConfidence", issueConfidenceStr)
              .build().toUri();
      HttpHeaders headers = new HttpHeaders();
      headers.setAccept(Collections.singletonList(MediaType.APPLICATION_OCTET_STREAM));

      HttpEntity<String> entity = new HttpEntity<>(headers);

      ResponseEntity<byte[]> response = restTemplate
            .exchange(uri, HttpMethod.GET, entity, byte[].class);

      if (response.getStatusCode() == HttpStatus.OK) {
         return response.getBody();
      }
      return null;
   }

   public void spider(String baseUrl) {
      String uriString = buildUriFromPathSegments("burp", "spider");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("baseUrl", baseUrl).build().toUri();
      restTemplate.postForLocation(uri, null);
   }

   public List<CookieInCookieJar> getCookieFromCookieJar() {
      String uriString = buildUriFromPathSegments("burp", "cookiejar");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("baseUrl", baseUrl).build().toUri();
      return restTemplate.getForObject(uri, new ArrayList<CookieInCookieJar>().getClass());

   }


   public void updateCookieInCookieJar(CookieInCookieJar cookie) {
      String uriString = buildUriFromPathSegments("burp", "cookiejar");
      URI uri = UriComponentsBuilder.fromUriString(uriString).queryParam("baseUrl", baseUrl).build().toUri();
      restTemplate.put(uri, List.of(cookie));
   }


   private String buildUriFromPathSegments(String... pathSegments) {
      return UriComponentsBuilder.fromUriString(baseUrl).pathSegment(pathSegments).toUriString();
   }
}
