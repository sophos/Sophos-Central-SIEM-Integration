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
import tempfile
import os
import config


class TestConfig(unittest.TestCase):
    """Test Config file items are exposed as attributes on config object"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="config_test", dir=".")

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def testReadingWhenAttributeExists(self):
        cfg_path = os.path.join(self.tmpdir, "config.ini")
        with open(cfg_path, "wb") as fp:
            fp.write("[login]\ntoken_info = MY_TOKEN\n".encode("utf-8"))
        cfg = config.Config(cfg_path)
        self.assertEqual(cfg.token_info, "MY_TOKEN")


class TestToken(unittest.TestCase):
    """Test the token gets parsed"""

    def testParse(self):
        txt = "url: https://anywhere.com/api, x-api-key: random, Authorization: Basic KJNKLJNjklNLKHB= "
        t = config.Token(txt)
        self.assertEqual(t.url, "https://anywhere.com/api")
        self.assertEqual(t.api_key, "random")
        self.assertEqual(t.authorization, "Basic KJNKLJNjklNLKHB=")
