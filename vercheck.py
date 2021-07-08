#!/usr/bin/env python3

# Copyright 2019-2021 Sophos Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and limitations under the
# License.
#
import sys

REQUIRED_VERSION_MAJOR = 3
REQUIRED_VERSION_MINOR = 6

if not (sys.version_info.major == REQUIRED_VERSION_MAJOR and sys.version_info.minor >= REQUIRED_VERSION_MINOR):
    print("Sophos SIEM requires Python %d.%d or higher!" % (REQUIRED_VERSION_MAJOR, REQUIRED_VERSION_MINOR))
    print("You are using Python %d.%d." % (sys.version_info.major, sys.version_info.minor))
    sys.exit(1)
