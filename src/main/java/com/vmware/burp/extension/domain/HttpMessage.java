/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.domain;

import burp.LegacyBurpExtender;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

//Returning full HTTP request and response
//@JsonIgnoreProperties(value = { "request", "response" })
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
public class HttpMessage {

   @XmlElement(required = true)
   private String host;

   @XmlElement(required = true)
   private int port;

   @XmlElement(required = true)
   private String protocol;

   @XmlElement(required = true)
   private URL url;

   @XmlElement(required = true)
   private short statusCode;

   @XmlTransient
   private byte[] request;

   @XmlTransient
   private byte[] response;

   @XmlElement(required = true)
   private String comment;

   @XmlElement(required = true)
   private String highlight;

   @XmlElement(required = true)
   private String method;

   @JsonProperty("responseHeaders")
   @XmlElement(required = true)
   private List<String> responseHeaders = new ArrayList<String>();

   @JsonProperty("cookies")
   @XmlElement(required = true)
   private List<Cookie> cookies = new ArrayList<Cookie>();

   @JsonProperty("parameters")
   @XmlElement(required = true)
   private List<Parameter> parameters = new ArrayList<Parameter>();

   public HttpMessage() {
   }

   public HttpMessage(IHttpRequestResponse iHttpRequestResponse) throws UnsupportedEncodingException {
      this.host = iHttpRequestResponse.getHttpService().getHost();
      this.port = iHttpRequestResponse.getHttpService().getPort();
      this.protocol = iHttpRequestResponse.getHttpService().getProtocol();
      this.request = iHttpRequestResponse.getRequest();
      this.response = iHttpRequestResponse.getResponse();
      this.comment = iHttpRequestResponse.getComment();
      this.highlight = iHttpRequestResponse.getHighlight();
      
      IExtensionHelpers helpers = LegacyBurpExtender.getInstance().getHelpers();
      IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
      this.url = requestInfo.getUrl();
      this.method = requestInfo.getMethod();
      for (IParameter iParameter : requestInfo.getParameters()) {
         this.parameters.add(new Parameter(iParameter));
      }
      
      if (iHttpRequestResponse.getResponse() != null) {
         IResponseInfo responseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());
         this.statusCode = responseInfo.getStatusCode();
         this.responseHeaders = responseInfo.getHeaders();
         for (ICookie iCookie : responseInfo.getCookies()) {
            this.cookies.add(new Cookie(iCookie));
         }
      }
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

   public URL getUrl() {
      return url;
   }

   public void setUrl(URL url) {
      this.url = url;
   }

   public short getStatusCode() {
      return statusCode;
   }

   public void setStatusCode(short statusCode) {
      this.statusCode = statusCode;
   }

   public byte[] getRequest() {
      return request;
   }

   public void setRequest(byte[] request) {
      this.request = request;
   }

   public byte[] getResponse() {
      return response;
   }

   public void setResponse(byte[] response) {
      this.response = response;
   }

   public String getComment() {
      return comment;
   }

   public void setComment(String comment) {
      this.comment = comment;
   }

   public String getHighlight() {
      return highlight;
   }

   public void setHighlight(String highlight) {
      this.highlight = highlight;
   }
   
   public String getMethod() {
      return method;
   }

   public void setMethod(String method) {
      this.method = method;
   }

   public List<String> getResponseHeaders() {
      return responseHeaders;
   }

   public void setResponseHeaders(List<String> responseHeaders) {
      this.responseHeaders = responseHeaders;
   }

   public List<Cookie> getCookies() {
      return cookies;
   }

   public void setCookies(List<Cookie> cookies) {
      this.cookies = cookies;
   }

   public List<Parameter> getParameters() {
      return parameters;
   }

   public void setParameters(List<Parameter> parameters) {
      this.parameters = parameters;
   }
}
