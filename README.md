# burp-rest-api

> ⚠️ **WARNING: This project is no longer actively maintained.**  
> While the repository will remain available for reference, no further updates, bug fixes, or support will be provided.  

## Overview

A REST/JSON API to the [Burp Suite](https://portswigger.net/burp) security tool.

Since the first commit back in 2016, **burp-rest-api** has been the default tool for BurpSuite-powered web scanning automation. Many security professionals and organizations have relied on this extension to orchestrate the work of Burp Spider and Scanner.

## Getting Started

1) Download the latest *burp-rest-api* JAR (e.g. `burp-rest-api-2.3.2.jar`) from the [release page](https://github.com/vmware/burp-rest-api/releases)
2) Place them within a directory having the **original** Burp Suite Professional JAR (e.g. *burpsuite_pro_v2025.6.3.jar*). **Important:** This is supposed to be the standalone JAR downloaded from https://portswigger.net/burp/releases. You should NOT use the `burpsuite_pro.jar` from a local Burp Suite installation
3) On Java 21, run *burp-rest-api* using:

On Linux, Mac `java --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED -cp "burpsuite_pro.jar:burp-rest-api-2.3.2.jar" org.springframework.boot.loader.launch.JarLauncher`

On Windows `java --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED -cp "burpsuite_pro.jar;burp-rest-api-2.3.2.jar" org.springframework.boot.loader.launch.JarLauncher`

**Important!!!** 
* Make sure to adjust the Burp Suite PRO and Burp Rest API JAR filenames
* The standalone Burp Suite PRO JAR for ARM64 doesn't seem to contain the Burp Browser, hence spidering and scanning won't work. We would highly recommend to run this software on x86

### Burp Suite Support and Limitations

**burp-rest-api** supports both the legacy Burp Suite Professional v1.7 and the newer Burp Suite Professional v2025.x. Since this project relies on [Burp Extender API](https://portswigger.net/burp/extender), the behaviour of certain functionalities might be slighlty different depending on the version of Burp. For example, the [Burp Suite Scanner configuration in v2025.x is no longer customizable](https://forum.portswigger.net/thread/scan-configuration-80c07e6d3e1080058). 

### Configuration

By default, Burp is launched in headless mode with the Proxy running on port 8080/tcp (**localhost only**) and the REST endpoint running on 8090/tcp (**localhost only**).

To __run Burp in UI mode__ from the command line, use one of the following commands:

```
    ./burp-rest-api.sh --headless.mode=false
```

On Java <= 1.8, it is also possible to execute burp-rest-api in the following way:

```
    java -jar burp-rest-api-2.3.2.jar --headless.mode=false --burp.jar=./lib/burpsuite_pro.jar
```

To __modify the server port__ on which the API is accessible, use one of the following commands:

```
    ./burp-rest-api.sh --server.port=8081
```
or
```
    ./burp-rest-api.sh --port=8081
```

You can also __modify the server address__, used for network address binding:

```
    ./burp-rest-api.sh --server.address=192.168.1.2
```
or
```
    ./burp-rest-api.sh --address=192.168.1.2
```

### Command Line Arguments

The following command line arguments are used only by the extension to configure the run mode and port number.

`--burp.jar=<filename.jar>` : Loads the Burp jar dynamically, and expose it through REST APIs. This flag works on Java <= 1.8 only! Use the `burp-rest-api.{sh,bat}` script for newer java versions.

`--burp.ext=<filename.{jar,rb,py}` : Loads the given Burp extensions during application startup. This flag can be repeated.

`--server.port=<port_number>` : The REST API endpoint is available at the given port number. `--port=<port_number>`
 works as short hand argument.
 
 `--server.address=<network address>` : Network address to which the REST API endpoint should bind. `--address=<address_ip>`
  works as short hand argument.
  
 `--apikey=<customApiKey>` : Enables API key authentication to protect APIs at **/burp/***. The customApiKey, if passed as an argument, must be included in every HTTP request as an additional header: **"API-KEY: <customApiKey\>"**.

`--headless.mode=<true/false>` : When set to false, runs Burp Suite in UI mode. Otherwise runs Burp Suite in headless
 mode. Default value: System Property (java.awt.headless)

Command line arguments passed to the executable burp-rest-api JAR are forwarded to the Burp Suite JAR. Hence, one may
 pass the following Burp Suite JAR command line arguments to the burp-rest-api JAR for the same functionality as if
 passing to the Burp Suite JAR directly.

`--project-file=<filename>` : Opens the specified **Data Project File** used for keeping the state of the tool. The file will be created as a new project if it doesn't
 exist already.

`--config-file=<filename>` : Opens the project using the options contained in the selected **Project Configuration File**. To load multiple project configurations, this argument can be passed more than once with different values. 
 
`--user-config-file=<filename>` : Opens the project using the options contained in the selected **User Configuration File**. To load multiple user configurations, this argument can be passed more than once with different values. 

For more information on *Projects*, refer to the Burp Suite documentation
 [here](https://portswigger.net/burp/help/suite_burp_projects.html) and [here](https://portswigger.net/blog/introducing-burp-projects). For scanner settings, please refer to the "Burp Suite Support and Limitations" section.

### Default Burp Configuration ###

If the burp-rest-api JAR is launched without the `--project-file`, `--config-file` or `--user-config-file` arguments, then Burp Suite is
 launched with a temporary project file and some default configuration. The temporary project file gets created upon
 launch of Burp Suite, and gets deleted at the end of the run.

For the default configuration used to launch Burp Suite, please refer to the files _burp-default-project-options.json_ and
_burp-default-user-options.json_ inside the JAR under the _static_ folder.

### HTTP API

[Swagger](http://swagger.io/) is used to define API documentation. Once the JAR is launched, access the following
 resources for API docs and Swagger UI. Port 8090 is the default server port.

API Docs: http://localhost:8090/v3/api-docs

Swagger UI: http://localhost:8090/swagger-ui/index.html#

### Client

This project also comes with a client (_BurpClient.java_) written in Java for use in other projects. Refer to the
 Integration Test file _BurpClientIT.java_ for the usage of _BurpClient.java_.

## Credits

This project is originally inspired from [Resty-Burp](https://github.com/continuumsecurity/resty-burp
 "continuumsecurity/resty-burp: REST/JSON interface to Burp Suite"), and is developed in partnership with [Doyensec LLC](https://doyensec.com/). <img src="https://doyensec.com/img/doyensec-logo.svg" width="300">

## Contributing

The burp-rest-api project team welcomes contributions from the community. If you wish to contribute code and you have
 not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For
 any questions about the CLA process, please refer to our [CLA FAQ](https://cla.vmware.com/faq). For more detailed
 information, refer to [CONTRIBUTING.md](CONTRIBUTING.md) and [FAQ.md](FAQ.md).

### Extension Development 

The following section contains useful information to get started with the development of the extension.

#### Prerequisites

* Java 21 x64
* Gradle
* Licensed Burp Suite Professional from: <http://portswigger.net/burp/>. Standalone JAR.

#### Build & Run

1. [Download](https://portswigger.net/burp/download.html) the Professional edition of Burp Suite JAR
2. The project can be run by directly launching the JAR created from building the project
3. Create a `lib` folder under the project directory and place the Burp Suite JAR file into it and rename it to "burpsuite_pro.jar" in order to run the integration tests

```
    # build the jar
    ./gradlew clean build
```

If you want to run the extension on recent (JRE > 9) versions of the JVM, use the `burp-rest-api-devel.{sh,bat}` launcher script after copying *burpsuite_pro.jar* and the *burp-rest-api.jar* in the same directory of the script.

```
# On Unix (Linux, macOS)
./burp-rest-api-devel.sh
# On Windows
./burp-rest-api-devel.bat
```

## License

Copyright (c) 2016 VMware, Inc. All Rights Reserved.
Copyright (c) 2025 Doyensec LLC. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 following conditions are met: Redistributions of source code must retain the above copyright notice, this list of
 conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation and/or other materials provided with the
 distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
