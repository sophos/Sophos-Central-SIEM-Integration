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
 Unit tests for Sophos SIEM Client.

 Requirements
  - Python 3.6+ (ActivePython recommended on Windows)
"""

import os
import shutil
import api_client
import sys
import unittest
import json
import time

from mock import MagicMock
from mock import patch


class Options:
    def __init__(self):
        self.quiet = False
        self.debug = True
        self.light = True
        self.since = False


class State:
    def __init__(self):
        self.state_data = {}


class Config:
    def __init__(self):
        self.filename = "syslog"
        self.facility = "daemon"
        self.address = "localhost:00"
        self.socktype = "udp"
        self.format = "json"
        self.client_id = ""
        self.client_secret = ""
        self.tenant_id = ""
        self.token_info = ""
        self.auth_url = ""
        self.api_host = ""


class TestApiClient(unittest.TestCase):
    def setUp(self):
        self.LOGGER_MOCK = MagicMock()
        api_client.SIEM_LOGGER = self.LOGGER_MOCK
        options = Options()
        state = State()
        config = Config()
        api_client.urlrequest.HTTPSHandler = MagicMock()
        api_client.urlrequest.build_opener = MagicMock()
        os.environ["SOPHOS_SIEM_HOME"] = "fake_sophos_siem_home"
        self.api_client = api_client.ApiClient(
            "/siem/v1/events", options, config, state
        )

    def tearDown(self):
        if os.path.exists("fake_sophos_siem_home/log"):
            shutil.rmtree("fake_sophos_siem_home")

    @patch("sys.stderr.write")
    def test_log(self, mock_sys_write):
        self.api_client.log("test")
        mock_sys_write.assert_called_once()
        mock_sys_write.assert_called_with("test\n")

    def test_get_syslog_facilities(self):
        result = self.api_client.get_syslog_facilities()
        self.assertIn("auth", result)

    @patch("time.sleep")
    def test_jitter(self, mock_time):
        result = self.api_client.jitter()
        mock_time.assert_called_once()

    @patch("api_client.logging.StreamHandler")
    def test_add_siem_logeer_handler_stdout(self, mock_handler):
        self.api_client.config.filename = "stdout"
        self.api_client.add_siem_logeer_handler("/fake_tmp/")
        mock_handler.assert_called_once()

    @patch("api_client.logging.FileHandler")
    def test_add_siem_logeer_handler_other(self, mock_handler):
        self.api_client.config.filename = "other"
        self.api_client.add_siem_logeer_handler("/fake_tmp/")
        mock_handler.assert_called_once()

    @patch("api_client.calendar.timegm")
    def test_get_past_datetime(self, mock_calender):
        self.api_client.get_past_datetime(12)
        mock_calender.assert_called_once()

    @patch("api_client.config.Token")
    @patch("api_client.urlrequest.Request")
    def test_get_alerts_or_events_with_token(self, mock_urlrequest, mock_token):
        mock_event_response = {
            "has_more": False,
            "next_cursor": "VjJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [],
        }
        self.api_client.make_token_request = MagicMock()
        self.api_client.make_token_request.return_value = mock_event_response
        response = self.api_client.get_alerts_or_events()
        self.assertEqual(response["next_cursor"], mock_event_response["next_cursor"])
        self.assertEqual(len(response["items"]), 0)
        self.api_client.options.since = 10
        response = self.api_client.get_alerts_or_events()
        self.assertEqual(response["next_cursor"], mock_event_response["next_cursor"])
        self.assertEqual(len(response["items"]), 0)

    @patch("sys.stderr.write")
    @patch("api_client.urlrequest.Request")
    def test_get_alerts_or_events_with_credentials(self, mock_urlrequest, sys_write):
        mock_event_response = {
            "has_more": False,
            "next_cursor": "TESJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [],
        }
        mock_tenant_response = {
            "id": 1,
            "idType": "test",
            "apiHost": "http://localhost",
            "name": "test tenant",
            "dataRegion": "test",
            "status": "active"
        }
        self.api_client.config.client_id = "test_client_id"
        self.api_client.config.client_secret = "test_client_secret"
        self.api_client.get_tenants_from_sophos = MagicMock()
        self.api_client.get_tenants_from_sophos.return_value = mock_tenant_response
        self.api_client.make_credentials_request = MagicMock()
        self.api_client.make_credentials_request.return_value = mock_event_response
        response = self.api_client.get_alerts_or_events()
        self.assertEqual(response["next_cursor"], mock_event_response["next_cursor"])
        self.assertEqual(len(response["items"]), 0)
        self.api_client.get_tenants_from_sophos.return_value = {"error": "error"}

        with self.assertRaises(Exception) as context:
            self.api_client.get_alerts_or_events()
        sys_write.assert_called_with("Error :: error\n")

    @patch("api_client.urlrequest.Request")
    def test_call_endpoint(self, mock_urlrequest):
        mock_response = {
            "has_more": False,
            "next_cursor": "VjJfQ1VSU09SfDIwMTktMDQtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [
                {
                    "when": "2019-04-01T15:11:09.759Z",
                    "id": "cbaff14f-a36b-46bd-8e83-6017ad79cdef",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "severity": "low",
                    "created_at": "2019-04-01T15:11:09.984Z",
                    "source_info": {"ip": "10.1.39.32"},
                    "endpoint_type": "server",
                    "endpoint_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                    "origin": None,
                    "type": "Event::Endpoint::Registered",
                    "location": "mock_Mercury_1",
                    "source": "n/a",
                    "group": "PROTECTION",
                    "name": "New server registered: mock_Mercury_1",
                },
                {
                    "when": "2019-04-01T15:11:41.000Z",
                    "id": "5bc48f19-3905-4f72-9f79-cd381c8e92ce",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "severity": "medium",
                    "created_at": "2019-04-01T15:11:41.053Z",
                    "source_info": {"ip": "10.1.39.32"},
                    "endpoint_type": "server",
                    "endpoint_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                    "origin": None,
                    "type": "Event::Endpoint::Threat::Detected",
                    "location": "mock_Mercury_1",
                    "source": "n/a",
                    "group": "MALWARE",
                    "name": "Malware detected: 'Eicar-AV-Test' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'",
                },
            ],
        }
        self.api_client.request_url = MagicMock()
        self.api_client.request_url.return_value = json.dumps(mock_response)
        response = self.api_client.call_endpoint("http://localhost", None, "")

        self.assertEqual(response["next_cursor"], mock_response["next_cursor"])
        self.assertEqual(len(response["items"]), 2)

    @patch("api_client.urlrequest.Request")
    def test_request_url(self, mock_urlrequest):
        mock_event_response = {
            "has_more": False,
            "next_cursor": "VjJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [],
        }
        self.api_client.opener.open = MagicMock()
        self.api_client.opener.open.return_value.read.return_value = mock_event_response
        response = self.api_client.request_url("http://localhost", None, "")
        self.assertEqual(response["has_more"], mock_event_response["has_more"])
        self.assertEqual(response["next_cursor"], mock_event_response["next_cursor"])
        self.assertEqual(len(response["items"]), 0)

    def test_get_alerts_or_events_req_args(self):
        self.api_client.options.light = True
        params = {"limit": 1000, "cursor": False}
        response = self.api_client.get_alerts_or_events_req_args(params)
        self.assertIn(
            "limit=1000&cursor=False&exclude_types=Event::Endpoint::NonCompliant",
            response,
        )
        self.api_client.options.light = False
        response = self.api_client.get_alerts_or_events_req_args(params)
        self.assertEqual(response, "limit=1000&cursor=False")

    def test_make_token_request(self):
        mock_response = {
            "has_more": False,
            "next_cursor": "TESJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [
                {
                    "severity": "high",
                    "threat": "TEST",
                    "endpoint_id": "123-131-3131-31313",
                    "endpoint_type": "test_type",
                    "source_info": {"ip": "0.0.0.0"},
                    "customer_id": "dadaf-test1213-sfsf-test",
                    "name": "test",
                    "id": "test-1213-1213-1213-1213",
                    "type": "test::testpoint::testfailed",
                    "group": "test",
                    "datastream": "test",
                    "end": "1999-03-24T12:45:33.273Z",
                    "duid": "test",
                    "rt": "1999-03-25T12:45:35.521Z",
                    "dhost": "test",
                    "suser": "test",
                }
            ],
        }
        mock_empty_items_response = {
            "has_more": False,
            "next_cursor": "TESJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [
            ],
        }
        self.api_client.state.save_state = MagicMock()
        self.api_client.call_endpoint = MagicMock()
        self.api_client.call_endpoint.return_value = mock_response
        response = self.api_client.make_token_request("events", MagicMock())
        self.assertEqual(list(response), mock_response["items"])

        self.api_client.call_endpoint.return_value = mock_empty_items_response
        response = self.api_client.make_token_request("events", MagicMock())
        self.assertEqual(list(response), mock_empty_items_response["items"])

    def test_make_credentials_request(self):
        tenant_response = {
            "access_token": "test_access_token",
            "has_more": False,
            "next_cursor": "TEST1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "id": "1",
            "apiHost": "http://localhost",
            "name": "test tenant",
            "dataGeography": "TE",
            "dataRegion": "te01",
            "status": "active"
        }
        mock_response = {
            "has_more": False,
            "next_cursor": "TESJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [
                {
                    "severity": "high",
                    "threat": "TEST",
                    "endpoint_id": "123-131-3131-31313",
                    "endpoint_type": "test_type",
                    "source_info": {"ip": "0.0.0.0"},
                    "customer_id": "dadaf-test1213-sfsf-test",
                    "name": "test",
                    "id": "test-1213-1213-1213-1213",
                    "type": "test::testpoint::testfailed",
                    "group": "test",
                    "datastream": "test",
                    "end": "1999-03-24T12:45:33.273Z",
                    "duid": "test",
                    "rt": "1999-03-25T12:45:35.521Z",
                    "dhost": "test",
                    "suser": "test",
                }
            ],
        }
        mock_empty_items_response = {
            "has_more": False,
            "next_cursor": "TESJfQ1VSU09SfDITESTETSTETtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [
            ],
        }
        self.api_client.state.save_state = MagicMock()
        self.api_client.call_endpoint = MagicMock()
        self.api_client.call_endpoint.return_value = mock_response
        response = self.api_client.make_credentials_request(
            "events", tenant_response
        )
        self.assertEqual(list(response), mock_response["items"])
        self.api_client.state_data = {"tenants": {"1": {"events": time.time() - 120}}}
        response = self.api_client.make_credentials_request(
            "events", tenant_response
        )
        self.assertEqual(list(response), mock_response["items"])


        self.api_client.call_endpoint.return_value = mock_empty_items_response
        response = self.api_client.make_credentials_request(
            "events", tenant_response
        )
        self.assertEqual(list(response), mock_empty_items_response["items"])


    def test_get_partner_tenants_from_sophos(self):
        whoami_response = {"id": "1", "idType": "partner"}
        token_response = {
            "access_token": "Test_Toekn",
        }
        partner_response = {"id": "1"}
        self.api_client.get_sophos_jwt = MagicMock()
        self.api_client.get_sophos_jwt.return_value = token_response
        self.api_client.get_whoami_data = MagicMock()
        self.api_client.get_whoami_data.return_value = whoami_response
        self.api_client.get_partner_organization_tenants = MagicMock()
        self.api_client.get_partner_organization_tenants.return_value = partner_response
        response = self.api_client.get_tenants_from_sophos()
        self.assertEqual(response, partner_response)

    def test_get_tenants_from_sophos_jwt_error(self):
        token_error_response = {"error": "error"}
        self.api_client.get_sophos_jwt = MagicMock()
        self.api_client.get_sophos_jwt.return_value = token_error_response
        response = self.api_client.get_tenants_from_sophos()
        self.assertEqual(response, token_error_response)

    @patch("sys.stderr.write")
    def test_get_tenants_from_sophos_jwt(self, mock_sys_write):
        whoami_response = {"id": "1", "idType": "tenant"}
        token_response = {
            "access_token": "Test_Toekn",
        }
        self.api_client.config.tenant_id = "1"
        self.api_client.get_sophos_jwt = MagicMock()
        self.api_client.get_sophos_jwt.return_value = token_response
        self.api_client.get_whoami_data = MagicMock()
        self.api_client.get_whoami_data.return_value = whoami_response
        response = self.api_client.get_tenants_from_sophos()
        self.assertEqual(
            response,
            {"access_token": "Test_Toekn", "id": "1", "idType": "tenant"},
        )
        self.api_client.config.tenant_id = "11"
        with self.assertRaises(Exception) as context:
            self.api_client.get_tenants_from_sophos()
        self.assertTrue(
            "Configuration file mention tenant id not matched with whoami data tenant id"
            in str(context.exception)
        )

    def test_get_tenants_from_sophos_empty_whoami(self):
        token_response = {
            "access_token": "Test_Toekn",
        }
        whoami_response = {}
        self.api_client.get_sophos_jwt = MagicMock()
        self.api_client.get_sophos_jwt.return_value = token_response
        self.api_client.get_whoami_data = MagicMock()
        self.api_client.get_whoami_data.return_value = whoami_response
        response = self.api_client.get_tenants_from_sophos()
        self.assertEqual(response, {})

    def test_get_sophos_jwt(self):
        token_response = {"access_token": "Test_Toekn", "expires_in": time.time()}
        self.api_client.config.client_id = "test_client_id"
        self.api_client.config.client_secret = "test_client_secret"
        self.api_client.state.save_state = MagicMock()
        self.api_client.request_url = MagicMock()
        self.api_client.request_url.return_value = json.dumps(token_response)
        response = self.api_client.get_sophos_jwt()
        self.assertEqual(response, token_response)

    def test_get_cache_sophos_jwt(self):
        token_response = {"access_token": "Test_Toekn", "expires_in": time.time()}
        self.api_client.config.client_id = "test_client_id"
        self.api_client.config.client_secret = "test_client_secret"
        self.api_client.state_data = {
            "account": {
                "test_client_id": {
                    "jwtExpiresAt": time.time() + 120,
                    "jwt": "old_token",
                }
            }
        }
        response = self.api_client.get_sophos_jwt()
        self.assertEqual(response, {"access_token": "old_token"})

    def test_get_whoami_data(self):
        whoami_response = {"id": "1", "idType": "tenant", "apiHost": "http://localhost"}
        self.api_client.config.api_host = "http://localhost"
        self.api_client.config.client_secret = "test_client_secret"
        self.api_client.state.save_state = MagicMock()
        self.api_client.request_url = MagicMock()
        self.api_client.request_url.return_value = json.dumps(whoami_response)
        response = self.api_client.get_whoami_data("test_token")
        self.assertEqual(response, whoami_response)

    def test_get_partner_organization_tenants(self):
        whoami_response = {
            "id": "1",
            "idType": "partner",
            "apiHosts": {"global": "http://localhost"},
        }

        tenant_response = {
            "items": [{"id": "1", "idType": "test", "apiHost": "http://localhost"}],
            "pages":{'current': 1, 'size': 100, 'total': 1, 'items': 1, 'maxSize': 100}
        }
        self.api_client.config.api_host = "http://localhost"
        self.api_client.config.tenant_id = "1"
        self.api_client.config.client_secret = "test_client_secret"
        self.api_client.state.save_state = MagicMock()
        self.api_client.request_url = MagicMock()
        self.api_client.request_url.return_value = json.dumps(tenant_response)
        response = self.api_client.get_partner_organization_tenants(
            whoami_response, "test_token"
        )
        self.assertEqual(response, tenant_response)


    def test_get_partner_organization_tenants_error(self):
        whoami_response = {
            "id": "1",
            "idType": "partner",
            "apiHosts": {"global": "http://localhost"},
        }

        tenant_response = {
        }
        self.api_client.config.api_host = "http://localhost"
        self.api_client.config.tenant_id = "1"
        self.api_client.config.client_secret = "test_client_secret"
        with self.assertRaises(Exception) as context:
            self.api_client.get_partner_organization_tenants(whoami_response, 'test_token')
        self.assertTrue(
            "Error getting tenant 1"
            in str(context.exception)
        )

    def test_get_partner_organization_tenants_empty_error(self):
        whoami_response = {
            "id": "1",
            "idType": "partner",
            "apiHosts": {"global": "http://localhost"},
        }

        tenant_response = {
        }
        self.api_client.config.api_host = "http://localhost"
        self.api_client.config.tenant_id = ""
        self.api_client.config.client_secret = "test_client_secret"
        with self.assertRaises(Exception) as context:
            self.api_client.get_partner_organization_tenants(whoami_response, 'test_token')
        self.assertTrue(
            "When using partner credentials, you must specify the tenant id in config.ini"
            in str(context.exception)
        )

    def test_get_since_value_option_given(self):
        self.api_client.options.since = expected_since = 18

        result = self.api_client.get_since_value("alert")

        self.assertEqual(result, expected_since)

    def test_get_since_value_option_not_given(self):
        expected_since = self.api_client.get_past_datetime(12)

        result = self.api_client.get_since_value("alert")

        self.assertEqual(result, expected_since)
