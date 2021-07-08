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


"""
 This script is for testing regressions after changes to Sophos SIEM.
 Requirements
  - Python 3.6+ (ActivePython recommended on Windows)
  - pycef module to decode CEF output. (https://github.com/DavidJBianco/pycef/)
    There is no equivalent for keyvalue, so that test is expected to fail at least half the time.
  - Some typical events in Central.

 Caveats:
  - Events arriving while the script is running may cause failures.
"""


import configparser as ConfigParser
import unittest
import shutil
import tempfile
import os
import json
import re
from urllib.request import Request, urlopen
import glob
import io
from zipfile import ZipFile
from subprocess import Popen, PIPE
import pycef


def find_python(ver):
    """Try to find Python of the given version.  Attempt to work on Windows and Linux"""
    win_python = glob.glob(
        "c:\\python%d*\\python.exe" % ver
    )  # assume Active Python on Windows
    if win_python:
        return win_python[0]
    else:
        return "python%d" % ver


class SIEMRunner:
    """Manage SIEM executions in a clean temporary directory, collect results"""

    def __init__(self, name):
        self.root = tempfile.mkdtemp(prefix=name, dir=".")
        self.cfg_path = os.path.join(self.root, "config.ini")
        self.keyval_rex = re.compile(
            r"^(?P<date>\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s(?P<keyvalue>.+)$"
        )

    def set_config(self, name, value):
        """Set a config value in the config.ini file"""
        config = ConfigParser.ConfigParser()
        config.read(self.cfg_path)
        config.set("login", name, value)
        with open(self.cfg_path, "w") as fp:
            config.write(fp)

    def get_config(self, name):
        """Read a config value from the config.ini file"""
        config = ConfigParser.ConfigParser()
        config.read(self.cfg_path)
        return config.get("login", name)

    def run_python(self, pypath, *args):
        """Run the script with given python interpreter (pypath) supplying *args"""
        before = os.getcwd()
        os.chdir(self.root)
        p = Popen([pypath, "siem.py"] + list(args), stdout=PIPE, stderr=PIPE)
        p.communicate("")
        retcode = p.wait()
        os.chdir(before)
        return retcode

    def run_python_version(self, ver, *args):
        exe = find_python(ver)
        self.run_python(exe, *args)

    def reset_state(self):
        """Remove state files, start over"""
        os.unlink(os.path.join(self.root, "state", "siem_sophos.json"))

    def get_results(self):
        """
        Find out where the results went, read, parse and return them if possible.
        """
        ofile = self.get_config("filename")
        out = []
        with open(os.path.join(self.root, "log", ofile)) as fp:
            for line in fp.readlines():
                data = line.strip()
                if not data:
                    continue
                if data.startswith("CEF"):
                    out.append(pycef.parse(data))
                    continue
                m = self.keyval_rex.match(data)
                if m:
                    out.append(m.groupdict())
                    continue

                out.append(json.loads(data))

        return out


def get_release():
    """Return the latest version of Sophos SIEM from github.  Cache it in the file 'master.zip'"""
    zip_location = (
        "https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/master.zip"
    )
    if not os.path.exists("master.zip"):
        fp = urlopen(Request(zip_location, method="HEAD"))
        zip_data = fp.read(int(fp.headers["Content-Length"]))
        fp.close()
        open("master.zip", "wb").write(zip_data)
    return open("master.zip", "rb").read()


def write_from_zip(zip_data, root):
    """Given a zip file as data, write the contents to the given root dir"""
    zf = io.BytesIO(zip_data)
    input_zip = ZipFile(zf)
    for name in input_zip.namelist():
        data = input_zip.read(name)
        ofile = os.path.basename(name)
        if ofile == "":
            continue  # don't extract directory entry.
        opath = os.path.join(root, ofile)
        with open(opath, "wb") as fp:
            fp.write(data)


def write_from_dir(srcdir, root):
    """Copy contents of the srcdir, to the root"""
    for i in os.listdir(srcdir):
        e = os.path.splitext(i)[1]
        if e in [".py", ".ini", ".txt"]:
            shutil.copyfile(i, os.path.join(root, i))


class BaseTest(unittest.TestCase):
    """Some utility functions used in the other tests"""

    def configure_all(self, name, value):
        """Write a config value to both SIEM Runners"""
        for runner in [self.orig_runner, self.new_runner]:
            runner.set_config(name, value)


class TestCompareOutput(BaseTest):
    """Test that old and new versions of the software are the same"""

    def setUp(self):
        # Create the original version install
        self.orig_runner = SIEMRunner("orig_py3")
        self.zip_data = get_release()
        write_from_zip(self.zip_data, self.orig_runner.root)

        # Create the new version install
        self.new_runner = SIEMRunner("new_py3")
        write_from_dir(".", self.new_runner.root)

        # Configure downloaded (original) version with the token from the version in cwd
        orig_token = self.orig_runner.get_config("token_info")
        self.assertTrue(
            orig_token.startswith("<")
        )  # we've got the as-shipped token text.  Expected.
        new_token = self.new_runner.get_config("token_info")
        self.assertTrue(new_token.startswith("url:"))  # Check the substitution

        self.orig_runner.set_config("token_info", new_token)

        # Set config common to all tests
        self.configure_all("filename", "result.txt")
        self.configure_all("endpoint", "event")

    def tearDown(self):
        for i in [self.orig_runner.root, self.new_runner.root]:
            if os.path.exists(i):
                shutil.rmtree(i)

    def RunBoth(self, ver, *args):
        """Run both versions and collect results as tuple."""
        self.orig_runner.run_python_version(ver, *args)
        self.new_runner.run_python_version(ver, *args)
        return self.orig_runner.get_results(), self.new_runner.get_results()

    def testJson(self):
        """Test the json output is identical between versions"""
        self.configure_all("format", "json")
        orig, new = self.RunBoth(3)
        self.assertEqual(orig, new)

    def testCEF(self):
        """Test the CEF output is identical between versions"""
        self.configure_all("format", "cef")
        orig, new = self.RunBoth(3)
        self.assertEqual(orig, new)

    def XXtestKeyValue(self):
        """
        Field order is dependent on Python dict.items() iteration order which isn't consistent between runs.
        This means keys can appear in any order, and without full parsing of keyvalue data, the comparison
        can't be done.
        If you need this test, comment it in (Remove XX above) and keep running it.
        It will pass approx 50% of the time.
        """
        self.configure_all("format", "keyvalue")
        orig, new = self.RunBoth(3)
        self.assertEqual(orig, new)

    def testJsonDifferentPython(self):
        """
        Run the new version and old version with Python3 and compare output.
        This should result in the same output.
        """
        self.configure_all("format", "json")
        self.orig_runner.run_python_version(3)
        orig = self.orig_runner.get_results()

        self.new_runner.run_python_version(3)
        new = self.new_runner.get_results()
        self.assertEqual(orig, new)


class TestNewFunctionality(BaseTest):
    def setUp(self):
        self.runner = SIEMRunner("new_py3")
        write_from_dir(".", self.runner.root)
        self.runner.set_config("format", "json")
        self.runner.set_config("filename", "result.txt")
        self.runner.set_config("endpoint", "event")

    def tearDown(self):
        if os.path.exists(self.runner.root):
            shutil.rmtree(self.runner.root)

    def testRunTwice(self):
        """Run the program twice, make sure the results file doesn't change in size"""
        self.runner.run_python_version(3)
        first_run = self.runner.get_results()
        self.runner.run_python_version(3)
        second_run = self.runner.get_results()

        self.assertEqual(first_run, second_run)

    def testRunWithStaleResults(self):
        """Run the program with some old data, make sure it doesn't get overwritten"""
        logdir = os.path.join(self.runner.root, "log")
        os.makedirs(logdir)
        ofile = os.path.join(logdir, self.runner.get_config("filename"))
        marker = '["SOME OLD JSON LOG DATA"]\r\n'.encode()
        with open(ofile, "wb") as fp:
            fp.write(marker)
        before_size = os.stat(ofile).st_size
        self.assertEqual(before_size, len(marker))
        self.runner.run_python_version(3)
        after_size = os.stat(ofile).st_size
        new_marker = open(ofile, "rb").read(len(marker))
        self.assertEqual(marker, new_marker)
        self.assertTrue(after_size > before_size)

    def testLightMode(self):
        noisy = ["Event::Endpoint::UpdateSuccess"]
        self.runner.run_python_version(3, "--light")
        for i in self.runner.get_results():
            # We know for sure this event will always be noisy.  Could check for the others.
            self.assertTrue(i["type"] not in noisy)
        # Make sure the
        self.runner.reset_state()
        self.runner.run_python_version(3)
        found = False
        for i in self.runner.get_results():
            # We know for sure this event will always be noisy. Could check for the others.
            if i["type"] in noisy:
                found = True
        self.assertTrue(found)  # we expect this event to appear all over the place.


if __name__ == "__main__":
    unittest.main()
