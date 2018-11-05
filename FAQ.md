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

Why does Burp ask me for activation when it was already activated?
----------------------------------------------------------------------------------------------

Any changes made to the Java Virtual Machine's user preferences might affect the Burp Suite license activation.

Keep in mind that [Burp Suite](https://support.portswigger.net/customer/portal/articles/1855756-burp-suite-software) as well as burp-rest-api require Java **x64** to run. Before activating Burp Suite for use with burp-rest-api, make sure your Java environment is properly installed, check your *JAVA_HOME* environment variable and depending on the OS in use, check that the currently active Java Runtime version is the same as *JAVA_HOME*. 

- **For Windows users**. Before attempting to install another JVM or upgrade JDK or change the JAVA_HOME make a backup of the following registry key : `Computer\HKEY_CURRENT_USER\Software\JavaSoft\Prefs\burp`. The currently active Java Runtime Versions can be checked from `Control Panel -> Java -> (General)(Update)Java -> View`.
- **For Linux users** Before making any changes to the Java environments make a backup of the following folder: `~/.java/.userPrefs/burp/`. Checking the currently active JVM versions can be done using different methods, depending on the distribution:
>* Archlinux : using `archlinux-java`
>* Debian/Ubuntu : using `sudo update-alternatives --config java`

