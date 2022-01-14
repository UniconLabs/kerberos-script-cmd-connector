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

For: Colorado School of Mines
Developed by: Unicon Inc. using existing TIRASA CMD Connector


This connector interfaces with Kerberos via an external script. Under the hood it uses and extends 
 the ConnId CMD connector (Tirasa ConnIdCMDBundle) and extends it in order to invoke a script for Kerberos commands and functions.

Currently, this connector is moderately coupled to the Colorado School of Mines Kerberos Perl script, but could be modified to be more
 customizable as desired. See the sample resource in the samples folder for and idea of configuration. 


You'll want to add this to the resource object in midPoint. Note you can tweak the timings to something that makes sense based on actual execution time of the script.
```xml
        <icfc:resultsHandlerConfiguration>
            <icfc:enableNormalizingResultsHandler>false</icfc:enableNormalizingResultsHandler>
            <icfc:enableFilteredResultsHandler>false</icfc:enableFilteredResultsHandler>
            <icfc:enableAttributesToGetSearchResultsHandler>false</icfc:enableAttributesToGetSearchResultsHandler>
        </icfc:resultsHandlerConfiguration>
        <icfc:timeouts>
            <icfc:create>180000</icfc:create>
            <icfc:get>180000</icfc:get>
            <icfc:update>180000</icfc:update>
            <icfc:delete>180000</icfc:delete>
            <icfc:test>60000</icfc:test>
            <icfc:scriptOnConnector>180000</icfc:scriptOnConnector>
            <icfc:scriptOnResource>180000</icfc:scriptOnResource>
            <icfc:authentication>60000</icfc:authentication>
            <icfc:search>180000</icfc:search>
            <icfc:validate>180000</icfc:validate>
            <icfc:sync>180000</icfc:sync>
            <icfc:schema>60000</icfc:schema>
        </icfc:timeouts>
```

If you want midPoint to delete/remove from the resource you may need to add, although for this connector it seems to work without (since there is no disable functionality):
```xml
<projection>
    <assignmentPolicyEnforcement>full</assignmentPolicyEnforcement>
</projection>
```