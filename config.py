#!/usr/bin/env python

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

import unittest
import shutil
import tempfile
import os
import re
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser


class Config:
    """Class providing config values"""
    def __init__(self, path):
        """Open the config file"""
        self.config = ConfigParser.ConfigParser()
        self.config.read(path)
        
    def __getattr__(self, name):
        return self.config.get('login', name)


class Token:
    def __init__(self, token_txt):
        """Initialize with the token text"""
        rex_txt = r"url\: (?P<url>https\://.+), x-api-key\: (?P<api_key>.+), Authorization\: (?P<authorization>.+)$"
        rex = re.compile(rex_txt)
        m = rex.search(token_txt)
        self.url = m.group("url")
        self.api_key = m.group("api_key")
        self.authorization = m.group("authorization").strip()


#
#  TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE
#  TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE TEST CODE
#


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
        cfg = Config(cfg_path)
        self.assertEqual(cfg.token_info, "MY_TOKEN")


class TestToken(unittest.TestCase):
    """Test the token gets parsed"""
    def testParse(self):
        txt = "  url: https://anywhere.com/api, x-api-key: random, Authorization: Basic KJNKLJNjklNLKHB= "
        t = Token(txt)
        self.assertEqual(t.url, "https://anywhere.com/api")
        self.assertEqual(t.api_key, "random")
        self.assertEqual(t.authorization, "Basic KJNKLJNjklNLKHB=")


if __name__ == '__main__':
    unittest.main()
