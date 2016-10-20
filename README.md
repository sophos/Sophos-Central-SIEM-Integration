# SIEM Script

#### Powered By Sophos Central
![N|Solid](https://www.sophos.com/en-us/medialibrary/SophosNext/Images/LP/SophosCentral/central-logo-cir.png?la=en)


This repository contains a sample for the SIEM endpoint of the Sophos Event
API. This sample is provided for reference purposes.

Any issues discovered using the samples should be reported on the Github
issues tracker.


### SIEM 

Script in this directory demonstrate how to use the SIEM Event API.

Access to the APIs requires access token that can be setup on Sophos Central UI by going to System Settings from navigation bar and then selecting API Token Management. From this page, you can click on Add Token button to create a new token.
Here is more information available on how to setup API Token: https://community.sophos.com/kb/en-us/125169

You can view API Swagger Specification by accessing API Access URL from the access token created under Api Token Management in Sophos Central UI.


### Installation ###

Download and extract from the following link
Script requires Python 2.7.9+ to run. Its not supported on Python 3.x.

### Configuration ###

SIEM script gets last 12 hours of events by default. Maximum 24 hours of historical data can be retrieved. Script keeps tab of its state, it will always pick-up from where it left off based on a state file stored in state folder. Script calls the server until there are no more events available. There is also a built-in retry mechanism if there are any network issues. Script exits if there are no more events available or when retry fails. In this case next scheduled run of the script will pick-up cursor from the last run using the state file.

Set SOPHOS_SIEM_HOME environment variable to point to the folder where config.ini, siem_cef_mapping.txt, state and log folders will be located. state and log folders are created when the script is run for the first time.

config.ini is a configuration file that exists by default in the siem-scripts folder.

Here are the steps to configure siem script:
1) Open config.ini in a text editor.
2) Under 'API Access URL + Headers' in the config file, copy and paste the API Access URL + Headers block from the Api Token Management page in Sophos Central.
3) Under json, cef or keyvalue, you could choose the preferred output of the response i.e. json, cef or keyvalue.
4) Under filename, you can specify the filename that your output would be saved to. Options are syslog, stdout or any custom file name. Custom files are created in a folder named log.
5) If you are using syslog then under syslog properties in the config file, configure address, facility and socktype.


### Running the script

Run 'python siem.py' and you should see the results as specified in the config file.
For more options and help on running the script run 'python siem.py -h'


### License

Copyright 2016 Sophos Limited

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
