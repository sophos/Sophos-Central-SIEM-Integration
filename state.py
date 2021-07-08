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
import sys
import os
import json
from pathlib import Path


class State:
    def __init__(self, options, state_file):
        """Class create state file and providing state file data"""

        if state_file and Path(state_file).suffix != ".json":
            raise SystemExit(
                "Sophos state file is not in valid format. it's must be with a .json extension"
            )
        self.options = options
        if "SOPHOS_SIEM_HOME" in os.environ:
            app_path = os.environ["SOPHOS_SIEM_HOME"]
        else:
            app_path = os.path.join(os.getcwd())

        self.state_file = self.get_state_file(app_path, state_file)
        self.create_state_dir(self.state_file)
        self.state_data = self.load_state_file()

    def log(self, log_message):
        """Write the log.
        Arguments:
            log_message {string} -- log content
        """
        if not self.options.quiet:
            sys.stderr.write("%s\n" % log_message)

    def create_state_dir(self, state_file):
        """Create state directory
        Arguments:
            state_file {string}: state file path
        """
        state_dir = os.path.dirname(state_file)
        if not os.path.exists(state_dir):
            try:
                os.makedirs(state_dir)
            except OSError as e:
                raise SystemExit("Failed to create %s, %s" % (state_dir, str(e)))

    def get_state_file(self, app_path, state_file):
        """Return state cache file path
        Arguments:
            app_path {string}: application path
            state_file {string}: state file path
        Returns:
            dict -- state file path
        """
        if not state_file:
            return os.path.join(app_path, "state", "siem_sophos.json")
        else:
            return (
                state_file
                if os.path.isabs(state_file)
                else os.path.join(app_path, state_file)
            )

    def load_state_file(self):
        """Get state file data
        Returns:
            dict -- Return state file data or exit if found any error
        """
        try:
            with open(self.state_file, "rb") as f:
                return json.load(f)
        except IOError:
            self.log("Sophos state file not found")
        except json.decoder.JSONDecodeError:
            raise SystemExit("Sophos state file not in valid JSON format")
        return {}

    def save_state(self, state_data_key, state_data_value):
        """save data in state file. Data store in nested object by splitting key with `.` separator
        Arguments:
            state_data_key {string}: state key
            state_data_value {string}: state value
        """
        # Store state
        key_arr = state_data_key.split(".")
        sub_data = self.state_data
        for item in key_arr[0:-1]:
            if item not in sub_data.keys():
                sub_data[item] = {}
            sub_data = sub_data[item]
        sub_data[key_arr[-1]] = state_data_value

        self.write_state_file(json.dumps(self.state_data, indent=4))

    def write_state_file(self, data):
        """Write data in state file
        Arguments:
            data {dict}: state data object
        """
        with open(self.state_file, "w") as f:
            try:
                f.write(data)
            except Exception as e:
                self.log("Error :: %s" % e)
                pass
