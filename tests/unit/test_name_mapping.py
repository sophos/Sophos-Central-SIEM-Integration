#!/usr/bin/env python3

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

import unittest
import copy
import name_mapping


def contains(dict_outer, dict_inner):
    return all(item in dict_outer.items() for item in dict_inner.items())


class TestNameExtraction(unittest.TestCase):
    """Test logging output"""

    def setUp(self):
        self.output = []

    def tearDown(self):
        pass

    def log(self, s):
        self.output.append(s)

    def testUpdateNameDLPValid(self):
        """DLP event with data that can be extracted"""
        data = {
            "type": "Event::Endpoint::DataLossPreventionUserAllowed",
            "name": u"An \u2033allow transfer on acceptance by user\u2033 action was taken.  "
            u"Username: WIN10CLOUD2\\Sophos  Rule names: \u2032test\u2032  User action: File open  "
            u"Application Name: Google Chrome  Data Control action: Allow  "
            u"File type: Plain text (ASCII/UTF-8)  File size: 36  "
            u"Source path: C:\\Users\\Sophos\\Desktop\\test.txt",
        }
        expected = {
            "type": "Event::Endpoint::DataLossPreventionUserAllowed",
            "name": "allow transfer on acceptance by user",
            "user": "WIN10CLOUD2\\Sophos",
            "rule": "test",
            "user_action": "File open",
            "app_name": "Google Chrome",
            "action": "Allow",
            "file_type": "Plain text (ASCII/UTF-8)",
            "file_size": "36",
            "file_path": "C:\\Users\\Sophos\\Desktop\\test.txt",
        }
        name_mapping.update_fields(self.log, data)
        self.assertTrue(all(item in data.items() for item in expected.items()))
        self.assertEqual(len(self.output), 0)

    def testUpdateNameThreatValid(self):
        """Threat event with data that can be extracted"""
        data = {
            "type": "Event::Endpoint::Threat::CleanedUp",
            "name": u"Threat 'EICAR' in 'myfile.com' ",
        }
        expected = {
            "type": "Event::Endpoint::Threat::CleanedUp",
            "name": u"EICAR",
            "filePath": "myfile.com",
            "detection_identity_name": "EICAR",
        }
        name_mapping.update_fields(self.log, data)
        self.assertTrue(contains(data, expected))  # expected data present
        self.assertEqual(len(self.output), 0)  # no error

    def testUpdateNameInvalid(self):
        """A known type, but information can't be extracted (regex mismatch)"""
        data = {
            "type": "Event::Endpoint::DataLossPreventionUserAllowed",
            "name": u"XXXX Garbage data XXXX",
        }
        before = copy.copy(data)
        name_mapping.update_fields(self.log, data)
        self.assertEqual(
            len(self.output), 1
        )  # a line of error output, when the function bails.
        self.assertEqual(data, before)  # ... and data remains unchanged

    def testUpdateNameFromDescription(self):
        """Ensure the name gets updated from the description, if present"""
        data = {"type": "", "description": "XXX"}
        expected = copy.copy(data)
        expected["name"] = "XXX"
        name_mapping.update_fields(self.log, data)
        self.assertEqual(data, expected)

    def testInvalidType(self):
        """Ensure that nothing gets changed when the type isn't recognised"""
        data = {"type": "<<Garbage>>", "name": "some name"}
        expected = copy.copy(data)
        name_mapping.update_fields(self.log, data)
        self.assertEqual(len(self.output), 0)  # not considered an error
        self.assertEqual(data, expected)

    def testSkippedType(self):
        """Ensure that entry is skipped if it's to be ignored."""
        # First find an event type that is set to 'None'
        toskip = None
        for k, v in name_mapping.TYPE_HANDLERS.items():
            if not v:
                toskip = k
                break
        data = {"type": toskip, "name": "some name"}
        expected = copy.copy(data)
        name_mapping.update_fields(self.log, data)
        self.assertEqual(len(self.output), 0)  # not considered an error
        self.assertEqual(data, expected)
