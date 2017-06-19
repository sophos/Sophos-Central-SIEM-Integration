#!/usr/bin/env python

# Copyright 2017 Sophos Limited
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
  - Python 2.7
  - pycef module to decode CEF output. (https://github.com/DavidJBianco/pycef/)
    There is no equivalent for keyvalue, so that test is expected to fail at least half the time.
 
 Caveats:
  - Events arriving while the script is running may cause failures.
 
"""


from ConfigParser import ConfigParser
import unittest, copy, shutil, tempfile, os, json, re, sys
import urllib2, glob
from StringIO import StringIO
from zipfile import ZipFile
from subprocess import Popen, PIPE
import pycef


class SIEMRunner:
    "Manage SIEM executions in a clean temporary directory, collect results"
    def __init__(self, name):
        self.root = tempfile.mkdtemp(prefix=name, dir=".")
        self.cfg_path = os.path.join(self.root, "config.ini")
        self.keyval_rex = re.compile(r"^(?P<date>\d\d\d\d-\d\d-\d\dT\d\d\:\d\d\:\d\d\.\d+Z)\s(?P<keyvalue>.+)$")

    def SetConfig(self, name, value):
        "Set a config value in the config.ini file"
        config = ConfigParser()
        config.read(self.cfg_path)
        config.set('login', name, value)
        with open(self.cfg_path, 'w') as fp:
            config.write(fp)

    def GetConfig(self, name):
        "Read a config value from the config.ini file"
        config = ConfigParser()
        config.read(self.cfg_path)
        return config.get('login', name)

    def RunPython(self, pypath, *args):
        "Run the script with given python interpreter (pypath) supplying *args"
        before = os.getcwd()
        os.chdir(self.root)
        p = Popen([pypath, "siem.py"]+ list(args), stdout = PIPE, stderr = PIPE)
        stdout, stderr = p.communicate("")
        retcode = p.wait()
        os.chdir(before)
        return retcode

    def FindPython(self, ver):
        "Try to find Python of the given version.  Attempt to work on Windows and Linux"
        win_python2 = glob.glob("c:\\python%d*\\python.exe" % ver)   # assume Active Python on Windows
        if win_python2:
            return win_python2[0]
        else:
            return "python%d" % ver

    def RunPythonVer(self, ver, *args):
        exe = self.FindPython(ver)
        self.RunPython(exe, *args)

    def ResetState(self):
        "Remove state files, start over"
        os.unlink(os.path.join(self.root, "state", "siem_lastrun_events.obj"))

    def GetResults(self):
        """
            Find out where the results went, read, parse and return them if possible.
        """
        ofile = self.GetConfig("filename")
        out = []
        with open(os.path.join(self.root, "log", ofile)) as fp:
            for line in fp.readlines():
                data = line.strip()
                if not data: continue
                if data.startswith("CEF"):
                    out.append(pycef.parse(data))
                    continue
                m = self.keyval_rex.match(data)
                if m:
                    out.append(m.groupdict())
                    continue

                out.append(json.loads(data))

        return out


class BaseTest(unittest.TestCase):
    "Some utility functions used in the other tests"

    def GetRelease(self):
        "Return the latest version of Sophos SIEM from github.  Cache it in the file 'master.zip'"
        zip_location = "https://github.com/sophos/Sophos-Central-SIEM-Integration/archive/master.zip"
        if not os.path.exists("master.zip"):
            fp = urllib2.urlopen(zip_location)
            zip_data = fp.read(int(fp.headers["Content-Length"]))
            fp.close()
            open("master.zip","wb").write(zip_data)
        return open("master.zip", "rb").read()
        
    def WriteFromZip(self, zip_data, root):
        "Given a zip file as data, write the contents to the given root dir"
        zf = StringIO(zip_data)
        input_zip=ZipFile(zf)
        for name in input_zip.namelist():
            data = input_zip.read(name)
            ofile = os.path.basename(name)
            if ofile == "": continue  # don't extract directory entry.
            opath = os.path.join(root, ofile)
            with open(opath, "wb") as fp:
                fp.write(data)

    def WriteFromDir(self, srcdir, root):
        "Copy contents of the srcdir, to the root"
        for i in os.listdir(srcdir):
            e = os.path.splitext(i)[1]
            if e in [".py", ".ini", ".txt"]:	        
                shutil.copyfile(i, os.path.join(root, i))

    def ConfigureAll(self, name, value):
        "Write a config value to both SIEM Runners"
        for runner in [self.orig_runner, self.new_runner]:
            runner.SetConfig(name, value)


class TestCompareOutput(BaseTest):
    "Test that old and new versions of the software are the same"

    def setUp(self):
        
        # Create the original version install
        self.orig_runner = SIEMRunner("orig_py2")
        self.zip_data = self.GetRelease()
        self.WriteFromZip(self.zip_data, self.orig_runner.root)

        # Create the new version install
        self.new_runner = SIEMRunner("new_py2")
        self.WriteFromDir(".", self.new_runner.root)

        # Configure downloaded (original) version with the token from the version in cwd
        orig_token = self.orig_runner.GetConfig("token_info")
        self.assertTrue(orig_token.startswith("<"))   # we've got the as-shipped token text.  Expected.
        
        new_token = self.new_runner.GetConfig("token_info")
        self.assertTrue(new_token.startswith("url:"))    # Check the substitution

        self.orig_runner.SetConfig("token_info", new_token)

        # Set config common to all tests
        self.ConfigureAll("filename", "result.txt")
        self.ConfigureAll("endpoint", "event")

    def tearDown(self):
        for i in [self.orig_runner.root, self.new_runner.root]:
            if os.path.exists(i):
                shutil.rmtree(i)

    def RunBoth(self, ver, *args):
        "Run both versions and collect results as tuple."
        self.orig_runner.RunPythonVer(ver, *args)
        self.new_runner.RunPythonVer(ver, *args)
        return self.orig_runner.GetResults(), self.new_runner.GetResults()

    def testJson(self):
        "Test the json output is identical between versions"
        self.ConfigureAll("format", "json")
        orig, new = self.RunBoth(2)
        self.assertEqual(orig, new)

    def testCEF(self):
        "Test the CEF output is identical between versions"
        self.ConfigureAll("format", "cef")
        orig, new = self.RunBoth(2)
        self.assertEqual(orig, new)

    def XXtestKeyValue(self):
        """
            Field order is dependent on Python dict.items() iteration order which isn't consistent between runs.
            This means keys can appear in any order, and without full parsing of keyvalue data, the comparison
            can't be done.
            If you need this test, comment it in (Remove XX above) and keep running it.  It will pass approx 50% 
            of the time.
        """
        self.ConfigureAll("format", "keyvalue")
        orig, new = self.RunBoth(2)
        self.assertEqual(orig, new)

    def testJsonDifferentPython(self):
        """
            Run the new version with Python3, old version with Python2 and compare output.
            This should result in the same output.
        """
        self.ConfigureAll("format", "json")
        self.orig_runner.RunPythonVer(2)
        orig = self.orig_runner.GetResults()

        self.new_runner.RunPythonVer(3)
        new = self.new_runner.GetResults()
        self.assertEqual(orig, new)


class TestNewFunctionality(BaseTest):

    def setUp(self):
        self.runner = SIEMRunner("new_py2")
        self.WriteFromDir(".", self.runner.root)
        self.runner.SetConfig("format", "json")
        self.runner.SetConfig("filename", "result.txt")
        self.runner.SetConfig("endpoint", "event")

    def tearDown(self):
        if os.path.exists(self.runner.root):
            shutil.rmtree(self.runner.root)

    def testRunTwice(self):
        "Run the program twice, make sure the results file doesn't change in size"
        self.runner.RunPythonVer(2)
        first_run = self.runner.GetResults()
        self.runner.RunPythonVer(2)
        second_run = self.runner.GetResults()

        self.assertEqual(first_run, second_run)

    def testRunWithStaleResults(self):
        "Run the program with some old data, make sure it doesn't get overwritten"
        logdir = os.path.join(self.runner.root, "log")
        os.makedirs(logdir)
        ofile = os.path.join(logdir, self.runner.GetConfig("filename"))
        
        marker = '["SOME OLD JSON LOG DATA"]\r\n'
        with open(ofile, "wb") as fp:
            fp.write(marker)
        before_size = os.stat(ofile).st_size
        self.assertEqual(before_size, len(marker))
        self.runner.RunPythonVer(2)
        after_size = os.stat(ofile).st_size
        new_marker = open(ofile, "rb").read(len(marker))
        self.assertEqual(marker, new_marker)
        self.assertTrue(after_size > before_size)

    def testLightMode(self):
        noisy = ["Event::Endpoint::UpdateSuccess"]
        self.runner.RunPythonVer(2, "--light")
        for i in self.runner.GetResults():
            # We know for sure this event will always be noisy.  Could check for the others.
            self.assertTrue(i["type"] not in noisy)
            
        # Make sure the 
        self.runner.ResetState()
        self.runner.RunPythonVer(2)
        found = False
        for i in self.runner.GetResults():
            # We know for sure this event will always be noisy.  Could check for the others.
            if i["type"] in noisy: 
                found = True
        self.assertTrue(found)   # we expect this event to appear all over the place.



if __name__ == '__main__':
    unittest.main()



