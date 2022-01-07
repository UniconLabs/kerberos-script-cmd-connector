<!--

    Copyright (C) 2011 ConnId (connid-dev@googlegroups.com)

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0
  
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

-->
Kerberos Command Connector
==============

This connector interfaces with Kerberos via an external Perl script. Under the hood it uses and extends 
 the ConnId CMD connector (Tirasa ConnIdCMDBundle) and extends it in order to invoke a Perl script for Kerberos commands and functions.


<a href="https://github.com/Tirasa/ConnIdCMDBundle/actions/workflows/ci.yml">
  <img src="https://github.com/Tirasa/ConnIdCMDBundle/actions/workflows/ci.yml/badge.svg"/>
</a>
<a href="#">
  <img src="https://img.shields.io/maven-central/v/net.tirasa.connid.bundles/net.tirasa.connid.bundles.cmd.svg"/>
</a>

## How to get it

### Maven

```XML
<dependency>
  <groupId>net.tirasa.connid.bundles</groupId>
  <artifactId>net.tirasa.connid.bundles.cmd</artifactId>
  <version>${connid.cmd.version}</version>
</dependency>
```

where `connid.cmd.version` is one of [available](http://repo1.maven.org/maven2/net/tirasa/connid/bundles/net.tirasa.connid.bundles.cmd/).
