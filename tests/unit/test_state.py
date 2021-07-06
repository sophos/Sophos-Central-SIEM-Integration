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
import shutil
import os
import mock
import state
import sys
from pathlib import Path


class Options:
    def __init__(self):
        self.quiet = False


class TestState(unittest.TestCase):
    """Test State file items are exposed as attributes on state object"""

    def setUp(self):
        options = Options()
        self.state = state.State(options, "/tmp/state/test_siem_sophos.json")

    def tearDown(self):
        if os.path.exists(self.state.state_file):
            state_dir = os.path.dirname(self.state.state_file)
            shutil.rmtree(state_dir)

    def test_init(self):
        path = Path("/tmp/state/")
        self.assertEqual(self.state.state_file, "/tmp/state/test_siem_sophos.json")
        self.assertEquals(path.parent.is_dir(), True)
        self.assertEqual(self.state.state_data, {})

    @mock.patch("state.State.get_state_file")
    @mock.patch("state.State.create_state_dir")
    @mock.patch("state.State.load_state_file")
    @mock.patch("sys.stderr.write")
    def test_log(self, mock_sys_write, mock_load_file, mock_state_dir, mock_state_file):
        self.state.log("test")
        mock_sys_write.assert_called_once()
        mock_sys_write.assert_called_with("test\n")

    @mock.patch("state.State.create_state_dir")
    @mock.patch("state.State.load_state_file")
    def test_get_state_file_with_empty_state_path(
        self, mock_load_file, mock_state_dir
    ):
        filepath = self.state.get_state_file("/tmp", None)
        self.assertEqual(filepath, "/tmp/state/siem_sophos.json")

    @mock.patch("state.State.get_state_file")
    @mock.patch("state.State.create_state_dir")
    @mock.patch("sys.stderr.write")
    def test_load_state_file_io_exception(
        self, mock_sys_write, mock_load_file, mock_state_dir
    ):
        self.state.state_file = "/tmp/test.json"
        self.state.load_state_file()
        mock_sys_write.assert_called_with("Sophos state file not found\n")

    def test_save_state(self):
        self.state.save_state("test.test_account", "test_account")
        self.state.load_state_file()
        self.assertEqual(
            self.state.state_data, {"test": {"test_account": "test_account"}}
        )
