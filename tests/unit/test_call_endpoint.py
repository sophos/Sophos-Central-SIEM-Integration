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
import unittest
import siem

import mock
import json


class CallEndPointTest(unittest.TestCase):

    @mock.patch('siem.config.Token')
    @mock.patch('siem.store_state')
    def test_data_stream_in_event(self,
                                  mock_cf_token,
                                  mock_store_state
                                  ):
        # Setup
        # Sample event
        mock_event_response = {
            "has_more": False,
            "next_cursor": "VjJfQ1VSU09SfDIwMTktMDQtMDFUMTg6MjU6NDEuNjA2Wg==",
            "items": [
                {
                    "when": "2019-04-01T15:11:09.759Z",
                    "id": "cbaff14f-a36b-46bd-8e83-6017ad79cdef",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "severity": "low",
                    "created_at": "2019-04-01T15:11:09.984Z",
                    "source_info": {
                        "ip": "10.1.39.32"
                    },
                    "endpoint_type": "server",
                    "endpoint_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                    "origin": None,
                    "type": "Event::Endpoint::Registered",
                    "location": "mock_Mercury_1",
                    "source": "n/a",
                    "group": "PROTECTION",
                    "name": "New server registered: mock_Mercury_1"
                },
                {
                    "when": "2019-04-01T15:11:41.000Z",
                    "id": "5bc48f19-3905-4f72-9f79-cd381c8e92ce",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "severity": "medium",
                    "created_at": "2019-04-01T15:11:41.053Z",
                    "source_info": {
                        "ip": "10.1.39.32"
                    },
                    "endpoint_type": "server",
                    "endpoint_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                    "origin": None,
                    "type": "Event::Endpoint::Threat::Detected",
                    "location": "mock_Mercury_1",
                    "source": "n/a",
                    "group": "MALWARE",
                    "name": "Malware detected: 'Eicar-AV-Test' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'"
                }
            ]
        }

        events = []
        # Run
        try:
            with mock.patch('siem.request_url') as mock_request_url:
                # mocking the request that retrieves events from SOA
                mock_request_url.return_value = json.dumps(mock_event_response)
                # call_endpoint uses yield method of python and returns each alert to the caller for
                # additional processing. Here its just appended to a list
                for e in siem.call_endpoint(mock.Mock(), siem.EVENT_TYPE, False, False, 'fake_state_file', mock_cf_token):
                    events.append(e)

        except Exception as ex:
            print ex

        # Verify
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["datastream"], siem.EVENT_TYPE)

    @mock.patch('siem.config.Token')
    @mock.patch('siem.store_state')
    def test_data_stream_in_alert(self,
                                  mock_cf_token,
                                  mock_store_state
                                  ):
        # Setup
        # Sample alert
        mock_alert_response = {
            "has_more": False,
            "next_cursor": "MHwyMDE5LTA0LTAxVDIxOjI2OjQ5LjIxOVo=",
            "items": [
                {
                    "severity": "high",
                    "when": "2019-04-01T16:11:10.487Z",
                    "threat": None,
                    "event_service_event_id": "d2fbaebe-c169-405e-946c-a2afbfb65ce2",
                    "id": "d2fbaebe-c169-405e-946c-a2afbfb65ce2",
                    "info": None,
                    "created_at": "2019-04-01T16:11:10.557Z",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "threat_cleanable": None,
                    "data": {
                        "created_at": 1554135070527,
                        "endpoint_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                        "endpoint_java_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                        "endpoint_platform": "windows",
                        "endpoint_type": "server",
                        "event_service_id": "d2fbaebe-c169-405e-946c-a2afbfb65ce2",
                        "inserted_at": 1554135070527,
                        "source_info": {
                            "ip": "10.1.39.32"
                        },
                        "user_match_id": "5ca22a0de5a7400deb1ab0bb"
                    },
                    "type": "Event::Endpoint::NotProtected",
                    "location": "mock_Mercury_1",
                    "description": "Failed to protect server: mock_Mercury_1",
                    "source": "n/a"
                },
                {
                    "severity": "high",
                    "when": "2019-04-01T16:14:17.147Z",
                    "threat": None,
                    "event_service_event_id": "69086f43-d619-4d03-a110-9a8cee3436f7",
                    "id": "69086f43-d619-4d03-a110-9a8cee3436f7",
                    "info": None,
                    "created_at": "2019-04-01T16:14:17.330Z",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "threat_cleanable": None,
                    "data": {
                        "created_at": 1554135257294,
                        "endpoint_id": "7a489a3a-0152-4b01-b1cc-c10d7f84f0bc",
                        "endpoint_java_id": "7a489a3a-0152-4b01-b1cc-c10d7f84f0bc",
                        "endpoint_platform": "windows",
                        "endpoint_type": "computer",
                        "event_service_id": "69086f43-d619-4d03-a110-9a8cee3436f7",
                        "inserted_at": 1554135257294,
                        "source_info": {
                            "ip": "10.1.39.32"
                        },
                        "user_match_id": "5ca22ac8e5a7400deb1ab0bd"
                    },
                    "type": "Event::Endpoint::NotProtected",
                    "location": "Lightning-oxidtdinku",
                    "description": "Failed to protect computer: Lightning-oxidtdinku",
                    "source": "Lightning-g7n7wdv611\\Lightning"
                },
                {
                    "severity": "high",
                    "when": "2019-04-01T15:11:41.000Z",
                    "threat": "Eicar-AV-Test",
                    "event_service_event_id": "30acdaed-5387-4a39-b7cd-d7b9ac2a8c0f",
                    "id": "30acdaed-5387-4a39-b7cd-d7b9ac2a8c0f",
                    "info": None,
                    "created_at": "2019-04-01T15:11:41.253Z",
                    "customer_id": "816f36ee-dd2e-4ccd-bb12-cea766c28ade",
                    "threat_cleanable": False,
                    "data": {
                        "created_at": 1554131501192,
                        "endpoint_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                        "endpoint_java_id": "c80c2a87-42f2-49b2-bab7-5031b69cd83e",
                        "endpoint_platform": "windows",
                        "endpoint_type": "server",
                        "event_service_id": "30acdaed-5387-4a39-b7cd-d7b9ac2a8c0f",
                        "inserted_at": 1554131501192,
                        "source_info": {
                            "ip": "10.1.39.32"
                        },
                        "threat_id": "5ca22a2c352ea40df121ea9c",
                        "user_match_id": "5ca22a0de5a7400deb1ab0bb"
                    },
                    "type": "Event::Endpoint::Threat::CleanupFailed",
                    "location": "mock_Mercury_1",
                    "description": "Manual cleanup required: 'Eicar-AV-Test' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'",
                    "source": "n/a"
                }
            ]
        }

        alerts = []
        # Run
        try:
            with mock.patch('siem.request_url') as mock_request_url:
                # mocking the request that retrieves alerts from SOA
                mock_request_url.return_value = json.dumps(mock_alert_response)
                # call_endpoint uses yield method of python and returns each alert to the caller for
                # additional processing. Here its just appended to a list
                for a in siem.call_endpoint(mock.Mock(), siem.ALERTS_V1, False, False, 'fake_state_file', mock_cf_token):
                    alerts.append(a)

        except Exception as ex:
            print ex

        # Verify
        self.assertEqual(len(alerts), 3)
        self.assertEqual(alerts[0]["datastream"], siem.ALERT_TYPE)

