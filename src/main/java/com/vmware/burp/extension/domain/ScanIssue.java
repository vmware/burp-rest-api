/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.domain;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.UnsupportedEncodingException;
import java.net.URL;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ScanIssue {

   @XmlElement(required = true)
   private URL url;

   @XmlElement(required = true)
   private String issueName;

   @XmlElement(required = true)
   private int issueType;

   @XmlElement(required = true)
   private String severity;

   @XmlElement(required = true)
   private String confidence;

   @XmlElement(required = true)
   private String issueBackground;

   @XmlElement(required = true)
   private String issueDetail;

   @XmlElement(required = true)
   private String remediationBackground;

   @XmlElement(required = true)
   private String remediationDetail;

   @XmlElement(required = true)
   private HttpMessage[] httpMessages;

   @XmlElement(required = true)
   private String host;

   @XmlElement(required = true)
   private int port;

   @XmlElement(required = true)
   private String protocol;

   private ScanIssue() {

   }

   public ScanIssue(IScanIssue iScanIssue) throws UnsupportedEncodingException {
      this.url = iScanIssue.getUrl();
      this.issueName = iScanIssue.getIssueName();
      this.issueType = iScanIssue.getIssueType();
      this.severity = iScanIssue.getSeverity();
      this.confidence = iScanIssue.getConfidence();
      this.issueBackground = iScanIssue.getIssueBackground();
      this.issueDetail = iScanIssue.getIssueDetail();
      this.remediationBackground = iScanIssue.getRemediationBackground();
      this.remediationDetail = iScanIssue.getRemediationDetail();
      this.host = iScanIssue.getHttpService().getHost();
      this.port = iScanIssue.getHttpService().getPort();
      this.protocol = iScanIssue.getHttpService().getProtocol();
      int length = iScanIssue.getHttpMessages().length;
      this.httpMessages = new HttpMessage[length];
      for (int i = 0; i < length; i++) {
         IHttpRequestResponse iHttpRequestResponse = iScanIssue.getHttpMessages()[i];
         this.httpMessages[i] = new HttpMessage(iHttpRequestResponse);
      }
   }

   public URL getUrl() {
      return url;
   }

   public void setUrl(URL url) {
      this.url = url;
   }

   public String getIssueName() {
      return issueName;
   }

   public void setIssueName(String issueName) {
      this.issueName = issueName;
   }

   public int getIssueType() {
      return issueType;
   }

   public void setIssueType(int issueType) {
      this.issueType = issueType;
   }

   public String getSeverity() {
      return severity;
   }

   public void setSeverity(String severity) {
      this.severity = severity;
   }

   public String getConfidence() {
      return confidence;
   }

   public void setConfidence(String confidence) {
      this.confidence = confidence;
   }

   public String getIssueBackground() {
      return issueBackground;
   }

   public void setIssueBackground(String issueBackground) {
      this.issueBackground = issueBackground;
   }

   public String getIssueDetail() {
      return issueDetail;
   }

   public void setIssueDetail(String issueDetail) {
      this.issueDetail = issueDetail;
   }

   public String getRemediationBackground() {
      return remediationBackground;
   }

   public void setRemediationBackground(String remediationBackground) {
      this.remediationBackground = remediationBackground;
   }

   public String getRemediationDetail() {
      return remediationDetail;
   }

   public void setRemediationDetail(String remediationDetail) {
      this.remediationDetail = remediationDetail;
   }

   public HttpMessage[] getHttpMessages() {
      return httpMessages;
   }

   public void setHttpMessages(HttpMessage[] httpMessages) {
      this.httpMessages = httpMessages;
   }

   public String getHost() {
      return host;
   }

   public void setHost(String host) {
      this.host = host;
   }

   public int getPort() {
      return port;
   }

   public void setPort(int port) {
      this.port = port;
   }

   public String getProtocol() {
      return protocol;
   }

   public void setProtocol(String protocol) {
      this.protocol = protocol;
   }
}
