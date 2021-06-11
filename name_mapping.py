# Copyright 2019-2021 Sophos Limited
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License.
# You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and limitations under the
# License.
#

import re


threat_regex = re.compile("'(?P<detection_identity_name>.*?)'.+'(?P<filePath>.*?)'")

# What to do with the different types of event. None indicates drop the event, otherwise a regex extracts the
# various fields and inserts them into the event dictionary.
TYPE_HANDLERS = {
    "Event::Endpoint::Threat::Detected": threat_regex,
    "Event::Endpoint::Threat::CleanedUp": threat_regex,
    "Event::Endpoint::Threat::HIPSDismissed": threat_regex,
    "Event::Endpoint::Threat::HIPSDetected": threat_regex,
    "Event::Endpoint::Threat::PuaDetected": threat_regex,
    "Event::Endpoint::Threat::PuaCleanupFailed": threat_regex,
    "Event::Endpoint::Threat::CleanupFailed": threat_regex,
    "Event::Endpoint::Threat::CommandAndControlDismissed": threat_regex,
    "Event::Endpoint::Threat::HIPSCleanupFailed": threat_regex,
    "Event::Endpoint::DataLossPreventionUserAllowed":
        re.compile(u"An \u2033(?P<name>.+)\u2033.+ Username: (?P<user>.+?) {2}"
                   u"Rule names: \u2032(?P<rule>.+?)\u2032 {2}"
                   "User action: (?P<user_action>.+?) {2}Application Name: (?P<app_name>.+?) {2}"
                   "Data Control action: (?P<action>.+?) {2}"
                   "File type: (?P<file_type>.+?) {2}File size: (?P<file_size>\\d+?) {2}"
                   "Source path: (?P<file_path>.+)$"),

    "Event::Endpoint::NonCompliant": None,    # None == ignore the event
    "Event::Endpoint::Compliant": None,
    "Event::Endpoint::Device::AlertedOnly": None,
    "Event::Endpoint::UpdateFailure": None,
    "Event::Endpoint::SavScanComplete": None,
    "Event::Endpoint::Application::Allowed": None,
    "Event::Endpoint::UpdateSuccess": None,
    "Event::Endpoint::WebControlViolation": None,
    "Event::Endpoint::WebFilteringBlocked": None,
}


def update_fields(log, data):
    """
        Split 'name' field into multiple fields based on regex and field names specified in TYPE_HANDLERS
        Original 'name' field is replaced with the detection_identity_name field, if returned by regex.
    """

    if u'description' in data.keys():
        data[u'name'] = data[u'description']

    if data[u'type'] in TYPE_HANDLERS:
        prog_regex = TYPE_HANDLERS[data[u'type']]
        if not prog_regex:
            return
        result = prog_regex.search(data[u'name'])
        if not result:
            log("Failed to split name field for event type %r" % data[u'type'])
            return

        # Make sure record has a name field corresponding to the first field (for the CEF format)
        gdict = result.groupdict()
        if "detection_identity_name" in gdict:
            data[u'name'] = gdict["detection_identity_name"]

        # Update the record with the split out parameters
        data.update(result.groupdict())
