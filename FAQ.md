FAQ
===

Is Burp Suite Free/Community edition supported?
-----------------------------------------------

No, it is not. Burp Rest API exposes functionalities that are best suited for the Professional 
version of Burp Suite. Even if it was possible to start _burp-rest-api_ using the Free version of Burp, this is no longer possible and the support won't be included in future releases.

Whenever I run the gradle command I receive an error. What can be the the cause?
----------------------------------------------------------------------------

Often times, Gradle introduces incompatibility between major versions, therefore
the recommended way of executing any Gradle build is by using the Gradle
Wrapper (in short just “Wrapper”). The Wrapper is a script that invokes a
declared version of Gradle, downloading it beforehand if necessary.

See [Issue 37](https://github.com/vmware/burp-rest-api/issues/37).

Is it possible to run burp-rest-api graphically in remote servers?
------------------------------------------------------------------

Yes, it is possible to run Burp in graphical environments in multiple
configurations (X Forwarding, Full VNC, RDP, XPRA).

For running a non persistent X Forwarding session on your OS you can follow this
[guide](https://uisapp2.iu.edu/confluence-prd/pages/viewpage.action?pageId=280461906).

See [Issue 60](https://github.com/vmware/burp-rest-api/issues/60).

Is it possible to customize the binding address:port for Burp Proxy and/or burp-rest-api APIs?
----------------------------------------------------------------------------------------------

There are two binding ports in a standard burp-rest-api setup:
- **burp-rest-api RPC mechanism**. Both IP address and port can be customized at runtime using command line arguments (namely _--server.address_ and _--server.port_)
- **Burp Proxy Listener**. This is a Burp Suite configuration, and can be customized using a custom project option file.

```
        "request_listeners":[
            {
                "certificate_mode":"per_host",
                "listen_mode":"192.168.1.1",
                "listener_port":8080,
                "running":true
            }
```

Is Burp Suite v2 supported?
----------------------------------------------------------------------------------------------

Next generation Burp Suite v2 is a beta release at the time of writing this FAQ. While we will *try* to mantain support for both Burp Suite stable and beta, we cannot ensure full compability. For production, please stay on Burp Suite Professional stable branch.
