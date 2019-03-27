# Copyright 2019 Sophos Limited
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
  - Python 2.7 (ActivePython recommended on Windows)
  - Python 3.5 (ActivePython recommended on Windows)
"""

import os
import siem
import sys
import unittest

from mock import MagicMock
from mock import patch


class CreateSIEMLogHandlerUnitTests(unittest.TestCase):

    @patch('logging.handlers.SysLogHandler')
    def test_syslog(self, mock):
        # Setup
        endpoint_config = {
            'filename': 'syslog',
            'address': 'fake_address',
            'facility': 'auth',
            'socktype': 'udp'
        }

        # Run
        handler = siem.create_siem_log_handler(endpoint_config)

        # Verify
        self.assertIsInstance(handler, type(mock.return_value))
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with('fake_address', 4, 2)

    @patch('logging.handlers.SysLogHandler')
    def test_syslog_with_port(self, mock):
        # Setup
        endpoint_config = {
            'filename': 'syslog',
            'address': 'fake_address:1234',
            'facility': 'cron',
            'socktype': 'tcp'
        }

        # Run
        handler = siem.create_siem_log_handler(endpoint_config)

        # Verify
        self.assertIsInstance(handler, type(mock.return_value))
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with(('fake_address', 1234), 9, 1)

    @patch('logging.StreamHandler')
    def test_stdout(self, mock):
        # Setup
        endpoint_config = {
            'filename': 'stdout',
        }

        # Run
        handler = siem.create_siem_log_handler(endpoint_config)

        # Verify
        self.assertIsInstance(handler, type(mock.return_value))
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with(sys.stdout)

    @patch('logging.FileHandler')
    def test_file(self, mock):
        # Setup
        endpoint_config = {
            'filename': 'fake_filename',
            'log_dir': 'fake_log_dir'
        }

        # Run
        handler = siem.create_siem_log_handler(endpoint_config)

        # Verify
        self.assertIsInstance(handler, type(mock.return_value))
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with(os.path.join('fake_log_dir', 'fake_filename'), 'a', encoding='utf-8')


class FormatUnitTests(unittest.TestCase):

    LOGGER_MOCK = None

    def setUp(self):
        self.LOGGER_MOCK = MagicMock()
        siem.SIEM_LOGGER = self.LOGGER_MOCK

    @patch("name_mapping.update_fields")
    def test_write_json_format(self, mock):
        # Setup
        results = [{
            'key': 'value'
        }]

        # Run
        siem.write_json_format(results)

        # Verify
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with(siem.log, results[0])
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 1)
        self.LOGGER_MOCK.info.assert_called_with(u'{"key": "value"}\n')

    @patch("name_mapping.update_fields")
    def test_write_keyvalue_format(self, mock):
        # Setup
        results = [{
            'rt': 'date'
        }]

        # Run
        siem.write_keyvalue_format(results)

        # Verify
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with(siem.log, results[0])
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 1)
        self.LOGGER_MOCK.info.assert_called_with(u'date rt="date";\n')

    @patch("name_mapping.update_fields")
    def test_write_cef_format(self, mock):
        # Setup
        results = [{
            'key': 'value'
        }]

        # Run
        siem.write_cef_format(results)

        # Verify
        self.assertEqual(mock.call_count, 1)
        mock.assert_called_with(siem.log, results[0])
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 1)
        self.LOGGER_MOCK.info.assert_called_with(u'CEF:0|sophos|sophos central|1.0|NA|NA|0|key=value\n')


class MainUnitTests(unittest.TestCase):

    LOGGER_MOCK = None

    def setUp(self):
        self.LOGGER_MOCK = MagicMock()
        siem.SIEM_LOGGER = self.LOGGER_MOCK

    @patch("siem.create_log_and_state_dir")
    @patch("siem.process_endpoint")
    @patch("siem.create_siem_log_handler")
    @patch("logging.FileHandler")
    @patch("config.Token")
    @patch("config.Config")
    def test_siem_logger(self,
                         mock_config,
                         mock_token,
                         mock_filehandler,
                         mock_create_siem_log_handler,
                         mock_process_endpoint,
                         mock_create_log_and_state_dir):
        # Setup
        os.environ['SOPHOS_SIEM_HOME'] = 'fake_sophos_siem_home'
        fake_endpoint_config = {
            'format': 'fake_format',
            'filename': 'fake_filename',
            'state_dir': os.path.join(os.environ['SOPHOS_SIEM_HOME'], 'state'),
            'log_dir': os.path.join(os.environ['SOPHOS_SIEM_HOME'], 'log'),
            'since': False
        }
        mock_config.return_value = MagicMock(format=fake_endpoint_config['format'],
                                             filename=fake_endpoint_config['filename'])

        # Run
        siem.main()

        # Verify
        self.assertEqual(self.LOGGER_MOCK.addHandler.call_count, 1)
        args, kwargs = mock_create_siem_log_handler.call_args
        self.assertEqual(len(args), 1)
        self.assertEqual(len(kwargs), 0)
        self.assertEqual(args[0], fake_endpoint_config)

    @patch("siem.create_log_and_state_dir")
    @patch("siem.process_endpoint")
    @patch("siem.create_siem_log_handler")
    @patch("logging.FileHandler")
    @patch("config.Token")
    @patch("config.Config")
    def test_siem_logger_with_syslog(self,
                                     mock_config,
                                     mock_token,
                                     mock_filehandler,
                                     mock_create_siem_log_handler,
                                     mock_process_endpoint,
                                     mock_create_log_and_state_dir):
        # Setup
        os.environ['SOPHOS_SIEM_HOME'] = 'fake_sophos_siem_home'
        fake_endpoint_config = {
            'format': 'fake_format',
            'filename': 'syslog',
            'state_dir': os.path.join(os.environ['SOPHOS_SIEM_HOME'], 'state'),
            'log_dir': os.path.join(os.environ['SOPHOS_SIEM_HOME'], 'log'),
            'since': False,
            'facility': 'fake_facility',
            'address': 'fake_address',
            'socktype': 'fake_socktype'
        }
        mock_config.return_value = MagicMock(format=fake_endpoint_config['format'],
                                             filename=fake_endpoint_config['filename'],
                                             facility=fake_endpoint_config['facility'],
                                             address=fake_endpoint_config['address'],
                                             socktype=fake_endpoint_config['socktype'])

        # Run
        siem.main()

        # Verify
        self.assertEqual(self.LOGGER_MOCK.addHandler.call_count, 1)
        args, kwargs = mock_create_siem_log_handler.call_args
        self.assertEqual(len(args), 1)
        self.assertEqual(len(kwargs), 0)
        self.assertEqual(args[0], fake_endpoint_config)
