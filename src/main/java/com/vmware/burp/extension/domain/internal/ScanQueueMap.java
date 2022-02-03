/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.domain.internal;

import burp.IScanQueueItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ScanQueueMap {
   private static final Logger log = LoggerFactory.getLogger(ScanQueueMap.class);
   // This map holds the url string as Key, and corresponding list of scan queue items for that url.
   private Map<String, List<IScanQueueItem>> map = new HashMap<>();

   public void addItem(String url, IScanQueueItem iScanQueueItem) {
      if (map.containsKey(url)) {
         List<IScanQueueItem> list = map.get(url);
         assert list != null;
         list.add(iScanQueueItem);
      } else {
         List<IScanQueueItem> list = new ArrayList<>();
         list.add(iScanQueueItem);
         map.put(url, list);
      }
   }

   public boolean hasUrl(String urlToSearch) {
      for (String url : map.keySet()) {
         if (url.equalsIgnoreCase(urlToSearch)) {
            log.info("Found the URL {} in Scan Queue", urlToSearch);
            return true;
         }
      }
      log.info("URL {} is NOT found in Scan Queue", urlToSearch);
      return false;
   }

   public Set<String> getUrls() {
      return map.keySet();
   }

   private List<IScanQueueItem> getQueue(String url) {
      return map.get(url);
   }

   public void clear() {
      map.clear();
   }

   public int getPercentageComplete() {
      if (map.keySet().size() == 0) {
         log.info("Scan Queue is empty. Returning the Percent Complete as 100%.");
         return 100;
      }

      int numberOfScans = 0;
      int totalPercentCompletion = 0;
      for (String url : map.keySet()) {
         for (IScanQueueItem iScanQueueItem : getQueue(url)) {
            numberOfScans++;
            if (iScanQueueItem.getStatus().equalsIgnoreCase("cancelled")
                    || iScanQueueItem.getStatus().contains("abandoned")
                    || iScanQueueItem.getStatus().contains("finished")) {
               totalPercentCompletion += 100;
            } else {
               // XXX: this method only works on BURP PRO  <= 1.7.+
               totalPercentCompletion += iScanQueueItem.getPercentageComplete();
            }
         }
      }

      if(totalPercentCompletion > 0) {
         int percentComplete = totalPercentCompletion / numberOfScans;
         log.info("Scan Percent Complete: {}", percentComplete);
         return percentComplete;
      }else{
         return 0;
      }
   }

   public List<String[]> getScanStatuses() {
      List<String[]> statuses = new ArrayList<>();
      for (String url : map.keySet()) {
         for (IScanQueueItem iScanQueueItem : getQueue(url)) {
            statuses.add(new String[]{url, iScanQueueItem.getStatus()});
         }
      }
      return statuses;
   }
}
