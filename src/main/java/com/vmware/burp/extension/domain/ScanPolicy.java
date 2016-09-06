/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.domain;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ScanPolicy {

   // Passive Checks
   public static String PASSIVE_SCAN_HEADERS = "scanner.testheaders";
   public static String PASSIVE_SCAN_MIME = "scanner.testmime";
   public static String PASSIVE_SCAN_FORMS = "scanner.testforms";
   public static String PASSIVE_SCAN_CACHING = "scanner.testcaching";
   public static String PASSIVE_SCAN_LINKS = "scanner.testlinks";
   public static String PASSIVE_SCAN_INFO_DISCLOSURE = "scanner.testinfodisclosure";
   public static String PASSIVE_SCAN_PARAMS = "scanner.testparams";
   public static String PASSIVE_SCAN_CLICKJACKING = "scanner.testclickjacking";
   public static String PASSIVE_SCAN_COOKIES = "scanner.testcookies";
   public static String PASSIVE_SCAN_VIEW_STATE = "scanner.testviewstate";
   public static String PASSIVE_SCAN_SERVER_ISSUES = "scanner.testserverissuespassive";

   //    private boolean passiveScanHeadersEnabled;
   //    private boolean passiveScanMimeEnabled;
   //    private boolean passiveScanFormsEnabled;
   //    private boolean passiveScanCachingEnabled;
   //    private boolean passiveScanLinksEnabled;
   //    private boolean passiveScanInfoDisclosureEnabled;
   //    private boolean passiveScanParamsEnabled;
   //    private boolean passiveScanClickjackingEnabled;
   //    private boolean passiveScanCookiesEnabled;
   //    private boolean passiveScanViewStateEnabled;
   //    private boolean passiveScanServerIssuesEnabled;

   @XmlElement(required = true)
   private PassiveScanPolicy passiveScanPolicy;

   public PassiveScanPolicy getPassiveScanPolicy() {
      return passiveScanPolicy;
   }

   public void setPassiveScanPolicy(
         PassiveScanPolicy passiveScanPolicy) {
      this.passiveScanPolicy = passiveScanPolicy;
   }

   public class ScanControl {
      private String configurationName;
      private boolean enabled;

      public String getConfigurationName() {
         return configurationName;
      }

      public void setConfigurationName(String configurationName) {
         this.configurationName = configurationName;
      }

      public boolean isEnabled() {
         return enabled;
      }

      public void setEnabled(boolean enabled) {
         this.enabled = enabled;
      }
   }

   public class PassiveScanPolicy {
      private ScanControl headers;
      private ScanControl mime;
      private ScanControl forms;
      private ScanControl caching;
      private ScanControl links;
      private ScanControl infoDisclosure;
      private ScanControl params;
      private ScanControl clickjacking;
      private ScanControl cookies;
      private ScanControl viewState;
      private ScanControl serverIssues;
   }
}
