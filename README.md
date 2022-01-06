# SIEM Script

#### Powered By Sophos Central

![N|Solid](https://www.sophos.com/en-us/medialibrary/SophosNext/Images/LP/SophosCentral/central-logo-cir.png?la=en)


This repository contains a script package to export event and alert data from Sophos Central into a SIEM solution.

Any issue discovered using the script should be reported to Sophos Support.


### SIEM

The script in this directory allows you to use the Sophos Central API to get data into your SIEM solution.

Access to the APIs requires API Credentials that can be setup in the Sophos Central UI by going to Global Settings from the navigation bar and then selecting API Credentials Management. From this page, you can click the Add Credential button to create new credentials (client ID and client secret).
Here is more information available on how to setup API Credentials: [https://community.sophos.com/kb/en-us/125169](https://community.sophos.com/kb/en-us/125169)


### Installation ###

Download and extract from [here](https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/v2.1.0.zip) for the latest release.
For older version, please consult the Releases section below.
For changes to the API, please consult the API Updates section below.
We recommend running this script with the latest version of Python 3.7 or newer. We have tested that this program works with Python 3.6 on multiple platforms. However, support for that version of Python will be dropped when it reaches end-of-life.

#### Releases ####

See [changelog](CHANGELOG.md) for full details.

##### [v2.1.0](https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/v2.1.0.zip) #####

* Bug fixes

##### [v2.0.1](https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/v2.0.1.zip) #####

* Added check for minimum supported Python version.

##### [v2.0.0](https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/v2.0.0.zip) #####

* New JWT-based authentication for the SIEM API
* Better support for partners and enterprise customers
* State file consolidated
* Drop support for Python 2.x

##### [v1.1.0](https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/v1.1.0.zip) #####

* CSA-2918: Adding text identifier to distinguish between an 'Event' and 'Alert'
* CSA-2917: Fixing issue with double alert reporting

##### [v1.0.0](https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/v1.0.0.zip) #####

* Initial release

#### API Updates ####

The following updates are part of an API update. They will be live for ***all versions of SIEM after their listed release dates.***

See [changelog](CHANGELOG.md) for full details.

##### 2019-04-13 #####

* Updated conversion logic to ensure matching identifiers between output objects for the following elements:
-- endpoint_id --	customer_id --	event_service_event_id

### Configuration ###

The script gets the last 12 hours of events on its initial run. A maximum of 24 hours of historical data can be retrieved. The script keeps tab of its state, it will always pick-up from where it left off based on a state file stored in the state folder. The script calls the server until there are no more events available. There is also a built-in retry mechanism if there are any network issues. The script exits if there are no more events available or when retry fails. In this case the next scheduled run of the script will pick-up state from the last run using the state file.

Set the SOPHOS_SIEM_HOME environment variable to point to the folder where config.ini, siem_cef_mapping.txt, state and log folders will be located. state and log folders are created when the script is run for the first time.

config.ini is a configuration file that exists by default in the siem-scripts folder.

##### Here are the steps to configure the script:

1. Open config.ini in a text editor.
2. Under Client ID and Client Secret in the config file, copy and paste the API Credentials from the API Credentials Management page in Sophos Central.
3. Under Customer tenant id in the config file, you can mention the tenant id for which you want to fetch alerts and events.

##### Optional configuration steps:

1. Under json, cef or keyvalue, you could choose the preferred output of the response i.e. json, cef or keyvalue.
2. Under filename, you can specify the filename that your output would be saved to. Options are syslog, stdout or any custom file name. Custom files are created in a folder named log.
3. If you are using syslog then under syslog properties in the config file, configure address, facility and socktype.
4. under state_file_path, specify the full or relative path to the cache file (with a ".json" extension)


### Running the script

Run `python siem.py` and you should see the results as specified in the config file. Here is the list of available options:

| Option | Description |
| ------ | ----------- |
| -s \<Unix Timestamp\>, --since=<Unix Timestamp> | Return results since specified Unix Timestamp, max last 24 hours, defaults to last 12 hours if there is no state file | 
| -c \<Config File Path\>, --config=<Config File Path> | Specify a configuration file, defaults to config.ini |
| -l, --light | Ignore noisy events: web control (`Event::Endpoint::WebControlViolation`, `Event::Endpoint::WebFilteringBlocked`), device control (`Event::Endpoint::Device::AlertedOnly`, `Event::Endpoint::SavScanComplete`), update success/failure (`Event::Endpoint::UpdateFailure`, `Event::Endpoint::UpdateSuccess`), application allowed (`Event::Endpoint::Application::Allowed`), (non)compliant (`Event::Endpoint::NonCompliant`, `Event::Endpoint::Compliant`) |
| -d, --debug | Print debug logs |
| -v, --version | Print version |
| -q, --quiet | Suppress status messages. No output would be printed by `siem.py` |


### License

Copyright 2016-2021 Sophos Limited

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
