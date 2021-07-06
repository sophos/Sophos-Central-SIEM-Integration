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

import re
import configparser as ConfigParser


class Config:
    """Class providing config values"""

    def __init__(self, path):
        """Open the config file"""
        self.config = ConfigParser.ConfigParser()
        self.config.read(path)

    def __getattr__(self, name):
        return self.config.get("login", name)


class Token:
    def __init__(self, token_txt):
        """Initialize with the token text"""
        rex_txt = r"url\: (?P<url>https\://.+), x-api-key\: (?P<api_key>.+), Authorization\: (?P<authorization>.+)$"
        rex = re.compile(rex_txt)
        m = rex.search(token_txt)
        self.url = m.group("url")
        self.api_key = m.group("api_key")
        self.authorization = m.group("authorization").strip()
