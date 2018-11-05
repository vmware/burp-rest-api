# burp-rest-api

## Overview

A REST/JSON API to the Burp Suite security tool.

Since version 2.0.0 it is possible to run the burp-rest-api release jar,
downloading it directly from the 
[release channel](https://github.com/vmware/burp-rest-api/releases).

## Documentation

### Configuration

By default, Burp is launched in headless mode with the Proxy running on port 8080/tcp (**localhost only**) and the REST endpoint running on 8090/tcp (**localhost only**).

To __run Burp in UI mode__ from the command line, use one of the following commands:

```
    java -jar burp-rest-api-2.0.0.jar --headless.mode=false --burp.jar=./lib/burpsuite_pro.jar
```


To __modify the server port__ on which the API is accessible, use one of the following commands:

```
    java -jar burp-rest-api-2.0.0.jar --server.port=8081 --burp.jar=./lib/burpsuite_pro.jar
```
or
```
    java -jar burp-rest-api-2.0.0.jar --port=8081 --burp.jar=./lib/burpsuite_pro.jar
```

You can also __modify the server address__, used for network address binding:

```
    java -jar burp-rest-api-2.0.0.jar --server.address=192.168.1.2 --burp.jar=./lib/burpsuite_pro.jar
```
or
```
    java -jar burp-rest-api-2.0.0.jar --address=192.168.1.2 --burp.jar=./lib/burpsuite_pro.jar
```

### Command Line Arguments

The following command line arguments are used only by the extension to configure the run mode and port number.

`--burp.jar=<filaname.jar>` : Loads the Burp jar dinamically, and expose it through REST APIs. This flag is required.

`--burp.ext=<filename.{jar,rb,py}` : Loads the given Burp extensions during application startup. This flag can be repeated.

`--server.port=<port_number>` : The REST API endpoint is available at the given port number. `--port=<port_number>`
 works as short hand argument.
 
 `--server.address=<network address>` : Network address to which the REST API endpoint should bind. `--address=<address_ip>`
  works as short hand argument.

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
 [here](https://portswigger.net/burp/help/suite_burp_projects.html) and [here](https://portswigger.net/blog/introducing-burp-projects).


### Default Burp Configuration ###

If the burp-rest-api JAR is launched without the `--project-file`, `--config-file` or `--user-config-file` arguments, then Burp Suite is
 launched with a temporary project file and some default configuration. The temporary project file gets created upon
 launch of Burp Suite, and gets deleted at the end of the run.

For the default configuration used to launch Burp Suite, refer to the files _burp-default-project-options.json_ and
_burp-default-user-options.json_ inside the JAR under the _static_ folder.

### HTTP API

[Swagger](http://swagger.io/) is used to define API documentation. Once the JAR is launched, access the following
 resources for API docs and Swagger UI. Port 8090 is the default server port.

API Docs: http://localhost:8090/v2/api-docs

Swagger UI: http://localhost:8090/swagger-ui.html#/

### Client

This project also comes with a client (_BurpClient.java_) written in Java for use in other projects. Refer to the
 Integration Test file _BurpClientIT.java_ for the usage of _BurpClient.java_.

## Credits

This project is originally inspired from [Resty-Burp](https://github.com/continuumsecurity/resty-burp
 "continuumsecurity/resty-burp: REST/JSON interface to Burp Suite"), and is developed in partnership with [Doyensec LLC](https://doyensec.com/). <img src="https://www.doyensec.com/images/logo.png" width="300">

## Contributing

The burp-rest-api project team welcomes contributions from the community. If you wish to contribute code and you have
 not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For
 any questions about the CLA process, please refer to our [CLA FAQ](https://cla.vmware.com/faq). For more detailed
 information, refer to [CONTRIBUTING.md](CONTRIBUTING.md) and [FAQ.md](FAQ.md).

### Develop

Upon successfully building the project, an executable JAR file is created.
The Burp suite JAR can be loaded dinamically through the `--burp.jar=` argument.
When the JAR is launched, it provides a REST/JSON endpoint to access the Scanner, Spider, Proxy and other
 features of the Burp Suite Professional security tool.

#### Prerequisites

* Java 8 x64
* Gradle
* Licensed Burp Suite Professional version 1.7.x or later from: <http://portswigger.net/burp/>


#### Build & Run

1. [Download](https://portswigger.net/burp/download.html) the Professional edition of Burp Suite.
2. The project can be run either by running the Gradle Spring `bootRun` command or by directly launching the JAR
 created from building the project:
3. OPTIONAL: Create a `lib` folder under the project directory and place the Burp Suite JAR file into it and rename it to "burpsuite_pro.jar" in order to run the integration tests.

```
    ./gradlew bootRun --burp.jar=./lib/burpsuite_pro.jar
```

or

```
    # build the jar
    ./gradlew clean build
    # and run it
    java -jar build/libs/burp-rest-api-2.0.0.jar --burp.jar=./lib/burpsuite_pro.jar 
```
The version number of the JAR should match the version number from `build.gradle` while generating the JAR.


## License

Copyright (c) 2016 VMware, Inc. All Rights Reserved.
Copyright (c) 2018 Doyensec LLC. All Rights Reserved.

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
