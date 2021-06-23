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


"""
 Unit tests for Sophos SIEM.

 Requirements
  - Python 3.5+ (ActivePython recommended on Windows)
"""

import os
import siem
import sys
import unittest

from mock import MagicMock
from mock import patch


class TestSiem(unittest.TestCase):

    LOGGER_MOCK = None

    def setUp(self):
        self.LOGGER_MOCK = MagicMock()
        siem.SIEM_LOGGER = self.LOGGER_MOCK

    @patch("name_mapping.update_fields")
    def test_write_json_format(self, mock_update_fields):
        # Setup
        results = [{"key": "value"}]

        # Run
        siem.write_json_format(results)

        # Verify
        self.assertEqual(mock_update_fields.call_count, 1)
        mock_update_fields.assert_called_with(siem.log, results[0])
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 1)
        self.LOGGER_MOCK.info.assert_called_with(u'{\n    "key": "value"\n}\n')

    @patch("name_mapping.update_fields")
    def test_write_keyvalue_format(self, mock_update_fields):
        # Setup
        results = [{"rt": "date"}]

        # Run
        siem.write_keyvalue_format(results)

        # Verify
        self.assertEqual(mock_update_fields.call_count, 1)
        mock_update_fields.assert_called_with(siem.log, results[0])
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 1)
        self.LOGGER_MOCK.info.assert_called_with(u'date rt="date";\n')

    @patch("name_mapping.update_fields")
    def test_write_cef_format(self, mock_update_fields):
        # Setup
        results = [{"key": "value"}]

        # Run
        siem.write_cef_format(results)

        # Verify
        self.assertEqual(mock_update_fields.call_count, 1)
        mock_update_fields.assert_called_with(siem.log, results[0])
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 1)
        self.LOGGER_MOCK.info.assert_called_with(
            u"CEF:0|sophos|sophos central|1.0|NA|NA|0|key=value\n"
        )

    def test_flatten_json(self):
        result = siem.flatten_json(1)
        self.assertEqual(result, {"": 1})

    @patch("sys.stderr.write")
    def test_log(self, mock_sys_write):
        QUIET = False
        siem.log("test")
        mock_sys_write.assert_called_once()
        mock_sys_write.assert_called_with("test\n")

    def test_format_prefix(self):
        result = siem.format_prefix("test\\1")
        self.assertEqual(result, "test\\\\1")

    def test_format_extension(self):
        result = siem.format_extension('"test"')
        self.assertEqual(result, '"test"')
        result = siem.format_extension({"test": '"test"'})
        self.assertEqual(result, {"test": '"test"'})

    def test_map_severity(self):
        result = siem.map_severity("low")
        self.assertEqual(result, 1)
        result = siem.map_severity("low_test")
        self.assertEqual(result, 0)

    def test_update_cef_keys(self):
        same_key_value_data = {"name": "test_name"}
        different_key_value_data = {"device_event_class_id": "test_type"}
        siem.update_cef_keys(same_key_value_data)
        self.assertEqual(same_key_value_data, {"name": "test_name"})
        siem.update_cef_keys(different_key_value_data)
        self.assertEqual(different_key_value_data, {"type": "test_type"})

    def test_format_cef(self):
        data = {
            "device_event_class_id": "Event::TestEndpoint::TestSuccess",
            "severity": "high",
            "source": "suser",
            "when": "end",
        }
        result = siem.format_cef(data)
        self.assertEqual(
            result,
            "CEF:0|sophos|sophos central|1.0|NA|NA|8|type=Event::TestEndpoint::TestSuccess suser=suser end=end",
        )

    def test_parse_args_options(self):
        options = siem.parse_args_options()
        self.assertEqual(options.since, False)
        self.assertEqual(options.quiet, False)
        self.assertEqual(options.version, False)

    @patch("config.Config")
    def test_load_config(self, mock_config):
        os.environ["SOPHOS_SIEM_HOME"] = "fake_sophos_siem_home"
        fake_endpoint_config = {
            "format": "json",
            "endpoint": "event",
            "filename": "syslog",
            "state_file_path": os.path.join(
                os.environ["SOPHOS_SIEM_HOME"], "state", "test.json"
            ),
            "log_dir": os.path.join(os.environ["SOPHOS_SIEM_HOME"], "log"),
            "since": False,
            "facility": "fake_facility",
            "address": "fake_address",
            "socktype": "fake_socktype",
        }
        mock_config.return_value = MagicMock(
            format=fake_endpoint_config["format"],
            endpoint=fake_endpoint_config["endpoint"],
            filename=fake_endpoint_config["filename"],
            state_file_path=os.path.join(
                os.environ["SOPHOS_SIEM_HOME"], "state", "test.json"
            ),
            facility=fake_endpoint_config["facility"],
            address=fake_endpoint_config["address"],
            socktype=fake_endpoint_config["socktype"],
        )

        config = siem.load_config("test/config.ini")
        self.assertEqual(config.format, fake_endpoint_config["format"])
        self.assertEqual(
            config.state_file_path, fake_endpoint_config["state_file_path"]
        )

    @patch("siem.write_cef_format")
    @patch("siem.write_keyvalue_format")
    @patch("siem.write_json_format")
    @patch("api_client.ApiClient")
    @patch("config.Config")
    def test_run(
        self,
        mock_config,
        mock_api_client,
        mock_json_format,
        mock_keyvalue_format,
        mock_cef_format,
    ):
        mock_api_client.return_value.get_alerts_or_events.return_value = MagicMock([])
        mock_config.return_value = MagicMock(endpoint="event", format="json")
        siem.run({}, mock_config, {})
        siem.write_json_format.assert_called_once()

    def test_validate_format(self):
        with self.assertRaises(Exception) as context:
            siem.validate_format("test")
        self.assertTrue(
            "Invalid format in config.ini, format can be json, cef or keyvalue"
            in str(context.exception)
        )

    def test_validate_endpoint(self):
        with self.assertRaises(Exception) as context:
            siem.validate_endpoint("test")
        self.assertTrue(
            "Invalid endpoint in config.ini, endpoint can be event, alert or all"
            in str(context.exception)
        )
