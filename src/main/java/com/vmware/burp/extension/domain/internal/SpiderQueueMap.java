/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.domain.internal;

import burp.LegacyBurpExtender;
import burp.IHttpRequestResponse;
import com.vmware.burp.extension.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class SpiderQueueMap {
    private static final Logger log = LoggerFactory.getLogger(SpiderQueueMap.class);
    private int timeBetweenChecks;
    // This map holds the url string as Key, and corresponding list of HTTP messages (siteMap) for that url.
    // Since Burp Extender APIs (as of v1.7.33) does not include a native method to check the status of the spider, we are periodically comparing the state of siteMap.
    private Map<String, IHttpRequestResponse[]> map = new HashMap<>();

    public SpiderQueueMap(int timeBetweenChecks){
        this.timeBetweenChecks = timeBetweenChecks;
    }

    public void addItem(String url, IHttpRequestResponse[] siteMapUrl) {
        if (map.containsKey(url)) {
            map.remove(url);
        }
        map.put(url, siteMapUrl);
    }

    public boolean hasUrl(String urlToSearch) {
        for (String url : map.keySet()) {
            if (url.equalsIgnoreCase(urlToSearch)) {
                log.info("Found the URL {} in Spider Queue", urlToSearch);
                return true;
            }
        }
        log.info("URL {} is NOT found in Spider Queue", urlToSearch);
        return false;
    }

    public Set<String> getUrls() {
        return map.keySet();
    }

    private IHttpRequestResponse[] getQueue(String url) {
        return map.get(url);
    }

    public void clear() {
        map.clear();
    }


    private boolean compareSiteMap(IHttpRequestResponse[] newSiteMap, IHttpRequestResponse[] oldSiteMap){
        if(newSiteMap.length != oldSiteMap.length) return false;

        boolean sameSiteMap = true;
        for(int i = 0; i < newSiteMap.length; i++) {
            if(!Arrays.equals(newSiteMap[i].getRequest(), oldSiteMap[i].getRequest()) || !Arrays.equals(newSiteMap[i].getResponse(), oldSiteMap[i].getResponse())){
                sameSiteMap = false;
            }
        }
        return sameSiteMap;
    }

    public int getPercentageComplete() throws MalformedURLException {
        if (map.keySet().size() == 0) {
            log.info("Spider Queue is empty. Returning the Percent Complete as 100%.");
            return 100;
        }

        // Forcing a delay while spidering is working in another thread, before comparing siteMaps
        try {
            Thread.sleep(timeBetweenChecks);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        int totalPercentCompletion = 0;
        for (String url : map.keySet()) {
            IHttpRequestResponse[] httpMessageListOld = map.get(url);
            IHttpRequestResponse[] httpMessageListNew = Utils.getSiteMapWrapper(url);

            if(compareSiteMap(httpMessageListNew, httpMessageListOld)){
                totalPercentCompletion += 100;
            }else{
                totalPercentCompletion += 0;
            }
        }

        map.replaceAll((url, v) -> {
            try {
                return Utils.getSiteMapWrapper(url);
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        });

        if(totalPercentCompletion > 0) {
            int percentComplete = totalPercentCompletion / map.size();
            log.info("Spider Percent Complete: {}", percentComplete);
            return percentComplete;
        }else{
            return 0;
        }
    }
}
