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
import calendar

import urllib.request as urlrequest
import urllib.error as urlerror
from urllib.parse import urlencode

import datetime
import json
import logging
import logging.handlers
import os
import socket
import name_mapping
from random import randint
import time
import config


SYSLOG_SOCKTYPE = {"udp": socket.SOCK_DGRAM, "tcp": socket.SOCK_STREAM}

# Initialize the SIEM_LOGGER
SIEM_LOGGER = logging.getLogger("SIEM")
SIEM_LOGGER.setLevel(logging.INFO)
SIEM_LOGGER.propagate = False
logging.basicConfig(format="%(message)s")

EVENTS_V1 = "/siem/v1/events"
ALERTS_V1 = "/siem/v1/alerts"

EVENT_TYPE = "event"
ALERT_TYPE = "alert"

ENDPOINT_MAP = {
    "event": [EVENTS_V1],
    "alert": [ALERTS_V1],
    "all": [EVENTS_V1, ALERTS_V1],
}

# Initialize the SIEM_LOGGER
SIEM_LOGGER = logging.getLogger("SIEM")


class ApiClient:
    def __init__(self, endpoint, options, config, state):
        """Class providing alerts and events data"""

        self.state = state
        self.state_data = state.state_data
        self.endpoint = endpoint
        self.options = options
        self.config = config
        logdir = self.create_log_dir()
        self.add_siem_logeer_handler(logdir)
        self.opener = self.create_request_builder()
        self.get_noisy_event_types = self.get_noisy_event_types()



    def get_noisy_event_types(self):
        """Return noisy event types
        Returns:
            list -- noisy event type list
        """
        return [k for k, v in name_mapping.TYPE_HANDLERS.items() if not v]

    def create_request_builder(self):
        """Create the request build
        Returns:
            dict -- request builder
        """
        if self.options.debug:
            handler = urlrequest.HTTPSHandler(debuglevel=1)
        else:
            handler = urlrequest.HTTPSHandler()

        return urlrequest.build_opener(handler)

    def create_log_dir(self):
        """Create the log directory
        Returns:
            log_dir {string} -- log directory path
        """
        if "SOPHOS_SIEM_HOME" in os.environ:
            app_path = os.environ["SOPHOS_SIEM_HOME"]
        else:
            app_path = os.path.join(os.getcwd())

        log_dir = os.path.join(app_path, "log")
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
                return log_dir
            except OSError as e:
                logging.error("Failed to create %s, %s" % (log_dir, str(e)))
                sys.exit(1)
        return log_dir

    def get_syslog_facilities(self):
        """Create a mapping between our names and the python syslog defines
        Returns:
            out {dict} -- syslog facilities
        """
        out = {}
        possible = (
            "auth cron daemon kern lpr mail news syslog user uucp "
            "local0 local1 local2 local3 local4 local5 local6 local7".split()
        )
        for facility in possible:
            out[facility] = getattr(
                logging.handlers.SysLogHandler, "LOG_%s" % facility.upper()
            )
        return out

    def jitter(self):
        """ Added the rendom sleep """
        time.sleep(randint(0, 10))

    def add_siem_logeer_handler(self, logdir):
        """Added the log handler
        Arguments:
            logdir {string}: log directory path
        """
        
        if self.config.filename == "syslog":
            
            syslog_facility = self.get_syslog_facilities()
            facility = syslog_facility[self.config.facility]
            address = self.config.address
            if ":" in address:
                result = address.split(":")
                host = result[0]
                port = result[1]
                address = (host, int(port))
            socktype = SYSLOG_SOCKTYPE[self.config.socktype]
            
            if socktype == socket.SOCK_STREAM : 
                #Check whether host is available within 3s for TCP!
                timeout_seconds = 3
                try:
                    sock = socket.create_connection(address, timeout=timeout_seconds)
                except :
                    logging.critical(f"Could not connect to {self.config.address} via TCP after {timeout_seconds} seconds")
                    raise SystemExit()
            else: #UDP
                logging.warning(f"Using UDP to connect to {self.config.address} - If target is not found, logs will be lost!")

            logging_handler = logging.handlers.SysLogHandler(
                address, facility, socktype
            )
            logging_handler.append_nul = self.config.append_nul == "true"
            
        elif self.config.filename == "stdout":
            logging_handler = logging.StreamHandler(sys.stdout)
        else:
            logging_handler = logging.FileHandler(
                os.path.join(logdir, self.config.filename), "a", encoding="utf-8"
            )
        if not SIEM_LOGGER.handlers:
            SIEM_LOGGER.addHandler(logging_handler)

    def get_past_datetime(self, hours):
        """Get the past datetime based on hours argument
        Arguments:
            hours {string}: number
        Returns:
            string -- return past datetime
        """
        return int(
            calendar.timegm(
                (
                    (
                        datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
                    ).timetuple()
                )
            )
        )

    def request_url(self, host_url, body, header, retry_count=3):
        """Make the request and return response data or throw exception
        Arguments:
            host_url {string}: req url
            body {dict}: req body
            header {dict}: req header
            retry_count {number}: retry request count
        Returns:
            response -- response data or throw exception
        """
        for i in range(0, retry_count):
            try:
                data = urlencode(body).encode("utf-8") if body is not None else body
                request = urlrequest.Request(host_url, data, header)
                response = self.opener.open(request)
            except urlerror.HTTPError as e:
                if e.code in (503, 504, 403, 429):
                    logging.error(
                        'Error "%s" (code %s) on attempt #%s of %s, retrying'
                        % (e, e.code, i, retry_count)
                       
                    )
                    if i < retry_count:
                        continue
                logging.error(
                    "Error during request. Error code: %s, Error message: %s"
                    % (e.code, e.read())
                    
                )
                raise
            return response.read()

    def get_alerts_or_events(self):
        """Get alerts/events data
        Returns:
            results {list} -- alerts/events response data
        """
        endpoint_name = self.endpoint.rsplit("/", 1)[-1]

        if self.options.light and self.endpoint == ENDPOINT_MAP["event"][0]:
            logging.info(
                "Light mode - not retrieving:%s" % "; ".join(self.get_noisy_event_types)
            )

        logging.info(
            "Config endpoint=%s, filename='%s' and format='%s'"
            % (self.endpoint, self.config.filename, self.config.format)
        )

        if (
            self.config.client_id
            and self.config.client_secret
        ):
            tenant_obj = self.get_tenants_from_sophos()

            if "id" in tenant_obj:
                results = self.make_credentials_request(
                   endpoint_name, tenant_obj
                )
            else:
                logging.critical(tenant_obj["error"])
                raise SystemExit()
        else:
            token_data = config.Token(self.config.token_info)
            results = self.make_token_request(
                endpoint_name, token_data
            )
        return results

    def call_endpoint(self, api_host, default_headers, args):
        """Execute the API request
        Arguments:
            api_host {string}: host name
            default_headers {object}: request header
            args {string}: request argument
        Returns:
            events {list} -- API response
        """
        events_request_url = "%s%s?%s" % (api_host, self.endpoint, args)
        logging.debug("URL: %s" % events_request_url)
        events_response = self.request_url(events_request_url, None, default_headers)
        if self.options.debug:
            logging.info("RESPONSE: %s" % events_response)
        events = json.loads(events_response)
        return events

    def get_alerts_or_events_req_args(self, params, endpoint_name):
        """Convert the params to query string
        Arguments:
            params {dict}: params object
        Returns:
            args {string} -- arguments string
        """
        if self.options.light and self.endpoint == ENDPOINT_MAP["event"][0]:
            types = ",".join(["%s" % t for t in self.get_noisy_event_types])
            types = "exclude_types=" + types
            args = "&".join(
                ["%s=%s" % (k, v) for k, v in params.items()]
                + [
                    types,
                ]
            )
        else:
            args = "&".join(["%s=%s" % (k, v) for k, v in params.items()])
            
        from_date_offset_minutes = self.config.alerts_from_date_offset_minutes
        if endpoint_name=="events":
            from_date_offset_minutes = self.config.events_from_date_offset_minutes
        args+='&from_date_offset_minutes='+str(from_date_offset_minutes)
        return args

    def make_token_request(self, endpoint_name, token):
        """Make alerts/events request by using token info.
        Arguments:
            endpoint_name {string}: endpoint name
            token {string} -- token
        Returns:
            dict -- yield event/alert object
        """
        state_data_key = endpoint_name + "LastFetched"
        default_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "X-Locale": "en",
            "Authorization": token.authorization,
            "x-api-key": token.api_key,
        }
        token_val = token.authorization.split()[1]

        params = {"limit": 1000}

        if (
            "account" in self.state_data
            and token_val in self.state_data["account"]
            and state_data_key in self.state_data["account"][token_val]
        ):
            params["cursor"] = self.state_data["account"][token_val][state_data_key]
            self.jitter()
        else:
            params["from_date"] = self.get_since_value(endpoint_name)


        while True:
            args = self.get_alerts_or_events_req_args(params, endpoint_name)
            events = self.call_endpoint(token.url, default_headers, args)

            if "items" in events and len(events["items"]) > 0:
                logging.info(f"Found {len(events['items'])} new events")
                for e in events["items"]:
                    e["datastream"] = EVENT_TYPE if (self.endpoint == EVENTS_V1) else ALERT_TYPE
                    yield e
            else:
                logging.info(
                    "No new %s data retrieved from the API"
                    % endpoint_name
                )
            data_key = "account." + token_val + "." + state_data_key
            self.state.save_state(data_key, events["next_cursor"])
            if not events["has_more"]:
                break
            else:
                params["cursor"] = events["next_cursor"]
                params.pop("from_date", None)

    def make_credentials_request(self, endpoint_name, tenant_obj):
        """Make alerts/events request by using API credentials.
        Arguments:
            endpoint_name {string}: endpoint name
            tenant_obj {object} -- tenant object
        Returns:
            dict -- yield event/alert object
        """
        state_data_key = endpoint_name + "LastFetched"
        tenant_id = tenant_obj["id"]
        default_headers = {
            "X-Tenant-ID": tenant_id,
            "Authorization": "Bearer " + tenant_obj["access_token"],
        }
        params = {"limit": 1000}

        if (
            "tenants" in self.state_data
            and tenant_id in self.state_data["tenants"]
            and state_data_key in self.state_data["tenants"][tenant_id]
        ):
            params["cursor"] = self.state_data["tenants"][tenant_id][state_data_key]
            self.jitter()
        else:
            params["from_date"] = self.get_since_value(endpoint_name)


        while True:
            args = self.get_alerts_or_events_req_args(params, endpoint_name)
            data_region_url = tenant_obj["apiHost"] if "idType" not in tenant_obj else tenant_obj["apiHosts"]["dataRegion"]
            events = self.call_endpoint(data_region_url, default_headers, args)
            if "items" in events and len(events["items"]) > 0:
                logging.info(f"Retrieved {len(events['items'])} new events")
                for e in events["items"]:
                    e["datastream"] = (
                        EVENT_TYPE if (self.endpoint == EVENTS_V1) else ALERT_TYPE
                    )
                    yield e
            else:
                logging.info(
                    "No new %s data retrieved from the API"
                    % endpoint_name
                )
            cursor_key = "tenants." + tenant_id + "." + state_data_key
            data_region_url_key = "tenants." + tenant_id + ".dataRegionUrl"
            last_run_key = "tenants." + tenant_id + ".lastRunAt"

            self.state.save_state(cursor_key, events["next_cursor"])
            self.state.save_state(data_region_url_key, data_region_url)
            self.state.save_state(last_run_key, time.time())
            if not events["has_more"]:
                break
            else:
                params["cursor"] = events["next_cursor"]
                params.pop("from_date", None)

    def get_since_value(self, endpoint_name):
        """Get the since time from options if provided else take default"""
        since = 12
        if self.options.since:
            since = self.options.since
            logging.info("Retrieving results since: %s" % since)
        else:
            logging.info("No datetime found for %s, defaulting to last 12 hours for results" % endpoint_name)
            since = self.get_past_datetime(12)
        return since

    def get_tenants_from_sophos(self):
        """Fetch the tenants for partner or organization.
        Get the tenants by calling Sophos tenant API.
        Returns:
            dict -- response containing either list of tenant or error
        """
        logging.debug("Fetching the tenants/customers list by calling the Sophos Cental API")
        response = self.get_sophos_jwt()

        if "access_token" in response:
            access_token = response["access_token"]
            whoami_response = self.get_whoami_data(access_token)
            if "id" in whoami_response:
                if (
                    whoami_response["idType"] == "partner"
                    or whoami_response["idType"] == "organization"
                ):
                    tenant_data = self.get_partner_organization_tenants(
                        whoami_response, access_token
                    )
                    tenant_data["access_token"] = access_token
                else:
                    if (
                        self.config.tenant_id != ""
                        and self.config.tenant_id
                        != whoami_response["id"]
                    ):
                        raise Exception(
                            "Configuration file mention tenant id not matched with whoami data tenant id"
                        )
                    else:
                        tenant_data = whoami_response
                        tenant_data["access_token"] = access_token
                return tenant_data
            else:
                logging.info(
                    "Whoami data not found for client id :: %s"
                    % self.config.client_id
                )
                return whoami_response
        else:
            logging.error(
                "JWT token not found for client id"
            )
            return response

    def get_sophos_jwt(self):
        """Fetch the Sophos JWT access token.
        Get the token by calling Sophos API.
        Returns:
            dict -- response containing either of jwt token or error
        """
        logging.debug("fetching access_token from sophos")
        client_id = self.config.client_id
        client_secret = self.config.client_secret
        body = {
            "grant_type": "client_credentials",
            "scope": "token",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        # NEVER LOG OUTPUT OF THE Authentication Parameters
        # If this goes to a syslog, you will expose critical information!
        #l.o.g.g.i.n.g.debug(("body :: %s" % str(body)))
        current_time = time.time()
        cache_client_data = (
            self.state_data["account"][client_id]
            if "account" in self.state_data and client_id in self.state_data["account"]
            else ""
        )

        if cache_client_data and current_time < cache_client_data["jwtExpiresAt"]:
            # NEVER LOG OUTPUT OF THE JWT TOKEN
            # If this goes to a syslog, you will expose critical information!
            #l.o.g.g.i.n.g.debug("return token from cache :: %s" % cache_client_data["jwt"])
            logging.debug("Found existing jwt token; Reusing")
            return {"access_token": cache_client_data["jwt"]}
        else:
            try:
                response = self.request_url(
                    self.config.auth_url, body, {}, retry_count=3
                )
                response_data = json.loads(response)

                self.state.save_state(
                    "account.%s.jwt" % client_id, response_data["access_token"]
                )
                self.state.save_state(
                    "account.%s.jwtExpiresAt" % client_id,
                    time.time() + (response_data["expires_in"] - 120),
                )
                logging.debug("Found existing jwt token; Reusing")
                return response_data
            except json.decoder.JSONDecodeError as e:
                logging.error("Sophos Token API response not in valid json format")
                return {"error": e}
            except Exception as e:
                logging.error(e)
                return {"error": e}

    def get_whoami_data(self, access_token):
        """Fetch the Whoami data.
        Get the customer/partner/organization data by calling Whoami API.
        Arguments:
            access_token {string}' JWT token value (default: {None})
        Returns:
            dict -- response containing whoami response or error
        """
        logging.debug("fetching whoami data")
        try:
            whoami_url = f"https://{self.config.api_host}/whoami/v1"
            default_headers = {"Authorization": "Bearer " + access_token}
            whoami_response = self.request_url(whoami_url, None, default_headers)

            logging.debug("Whoami response: %s" % whoami_response)
            whoami_data = json.loads(whoami_response)
            self.state.save_state(
                "account.%s.whoami" % self.config.client_id, whoami_data
            )
            return whoami_data
        except json.decoder.JSONDecodeError as e:
            logging.error("Sophos whoami API response not in json format")
            return {"error": e}
        except Exception as e:
            logging.error(e)
            return {"error": e}

    def get_partner_organization_tenants(self, whoami_response, access_token):
        """Get the tenants for partner and organization by calling tenant API.
        Arguments:
            whoami_response {object}: whoami data
            access_token {string}' JWT token value (default: {None})
        Returns:
            dict -- response containing whoami response or error
        """
        if not self.config.tenant_id:
            raise Exception(
                f"When using {whoami_response['idType']} credentials, you must specify the tenant id in config.ini"
            )

        tenant = {}
        try:
            if whoami_response["idType"] == "organization":
                default_headers = {
                    "Authorization": "Bearer " + access_token,
                    "X-Organization-ID": whoami_response["id"],
                }
            else:
                default_headers = {
                    "Authorization": "Bearer " + access_token,
                    "X-Partner-ID": whoami_response["id"],
                }

            tenant_url = (
                whoami_response["apiHosts"]["global"]
                + "/"
                + whoami_response["idType"]
                + "/v1/tenants/"
                + self.config.tenant_id
            )
            tenant_response = self.request_url(tenant_url, None, default_headers, 1)

            logging.info("Tenant response: %s" % (tenant_response))
            return json.loads(tenant_response)

        except json.decoder.JSONDecodeError as e:
            logging.error(f"Sophos {whoami_response['idType']} tenant API response not in json format")
            return {"error": e}
        except Exception as e:
            raise Exception(
                    f"Error getting tenant {self.config.tenant_id}, {e}"
            )
