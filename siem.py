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
import sys
import calendar


try:
    # Python 2
    import urllib2 as urlrequest
    import urllib2 as urlerror
    from urllib import urlencode
except ImportError:
    # Python 3
    import urllib.request as urlrequest
    import urllib.error as urlerror
    from urllib.parse import urlencode


import datetime
import json
import logging
import logging.handlers
import os
import pickle
import re
import socket
import time

from optparse import OptionParser
from random import randint
import name_mapping
import config


def get_syslog_facilities():
    """Create a mapping between our names and the python syslog defines"""
    out = {}
    possible = "auth cron daemon kern lpr mail news syslog user uucp " \
               "local0 local1 local2 local3 local4 local5 local6 local7".split()
    for facility in possible:
        out[facility] = getattr(logging.handlers.SysLogHandler, "LOG_%s" % facility.upper())
    return out


SYSLOG_FACILITY = get_syslog_facilities()


SYSLOG_SOCKTYPE = {'udp': socket.SOCK_DGRAM,
                   'tcp': socket.SOCK_STREAM
                   }


VERSION = '1.0.0'
LIGHT = False
DEBUG = False
QUIET = False
MISSING_VALUE = 'NA'
DEFAULT_ENDPOINT = 'event'
PREFIX_PATTERN = re.compile(r'([|\\])')
EXTENSION_PATTERN = re.compile(r'([=\\])')

SEVERITY_MAP = {'none': 0,
                'low': 1,
                'medium': 5,
                'high': 8,
                'very_high': 10}


def get_noisy_event_types():
    return [k for k, v in name_mapping.TYPE_HANDLERS.items() if not v]


NOISY_EVENTTYPES = get_noisy_event_types()

EVENTS_V1 = '/siem/v1/events'
ALERTS_V1 = '/siem/v1/alerts'
OAUTH2_TOKEN_V2 = ''

EVENT_TYPE = 'event'
ALERT_TYPE = 'alert'

ENDPOINT_MAP = {'event': [EVENTS_V1],
                'alert': [ALERTS_V1],
                'all': [EVENTS_V1, ALERTS_V1]}

CEF_CONFIG = {'cef.version': '0', 'cef.device_vendor': 'sophos',
              'cef.device_product': 'sophos central', 'cef.device_version': 1.0}

# CEF format from https://www.protect724.hpe.com/docs/DOC-1072
CEF_FORMAT = ('CEF:%(version)s|%(device_vendor)s|%(device_product)s|'
              '%(device_version)s|%(device_event_class_id)s|%(name)s|%(severity)s|')


CEF_MAPPING = {
    # This is used for mapping CEF header prefix and extension to json returned by server
    # CEF header prefix to json mapping
    # Format
    # CEF_header_prefix: JSON_key
    "device_event_class_id": "type",
    "name": "name",
    "severity": "severity",
    
    # json to CEF extension mapping
    # Format
    # JSON_key: CEF_extension
    "source": "suser",
    "when": "end",
    "user_id": "duid",
    "created_at": "rt",
    "full_file_path": "filePath",
    "location": "dhost",
}

# Initialize the SIEM_LOGGER
SIEM_LOGGER = logging.getLogger('SIEM')
SIEM_LOGGER.setLevel(logging.INFO)
SIEM_LOGGER.propagate = False
logging.basicConfig(format='%(message)s')


def main():
    global LIGHT, DEBUG, QUIET

    if 'SOPHOS_SIEM_HOME' in os.environ:
        app_path = os.environ['SOPHOS_SIEM_HOME']
    else:
        # Setup path
        app_path = os.path.join(os.getcwd())

    config_file = os.path.join(app_path, 'config.ini')

    parser = OptionParser(description="Download event and/or alert data and output to various formats. "
                                      "config.ini is a configuration file that exists by default in the siem-scripts "
                                      "folder."
                                      "Script keeps tab of its state, it will always pick-up from where it left-off "
                                      "based on a state file stored in state folder. Set SOPHOS_SIEM_HOME environment "
                                      "variable to point to the folder where config.ini, mapping files, state "
                                      "and log folders will be located. state and log folders are created when the "
                                      "script is run for the first time. ")
    parser.add_option('-s', '--since', default=False, action='store', help="Return results since specified Unix "
                                                                           "Timestamp, max last 24 hours, defaults to "
                                                                           "last 12 hours if there is no state file")
    parser.add_option('-c', '--config', default=config_file, action='store', help="Specify a configuration file, "
                                                                                  "defaults to config.ini")
    parser.add_option('-l', '--light', default=False, action='store_true', help="Ignore noisy events - web control, "
                                                                                "device control, update failure, "
                                                                                "application allowed, (non)compliant")
    parser.add_option('-d', '--debug', default=False, action='store_true', help="Print debug logs")
    parser.add_option('-v', '--version', default=False, action='store_true', help="Print version")
    parser.add_option('-q', '--quiet', default=False, action='store_true', help="Suppress status messages")

    options, args = parser.parse_args()

    if options.config is None:
        parser.error("Need a config file specified")

    if options.version:
        log(VERSION)
        sys.exit(0)
    if options.quiet:
        QUIET = True

    # Read config file
    cfg = config.Config(options.config)
    token = config.Token(cfg.token_info)
    client = {
        'client_id': cfg.client_id,
        'client_secret': cfg.client_secret,
        'x_tenant_id': cfg.x_tenant_id
    }
    
    log("Config loaded, retrieving results for '%s'" % token.api_key)
    log("Config retrieving results for '%s'" % token.authorization)

    if cfg.endpoint in ENDPOINT_MAP:
        tuple_endpoint = ENDPOINT_MAP[cfg.endpoint]
    else:
        tuple_endpoint = ENDPOINT_MAP[DEFAULT_ENDPOINT]

    state_dir = os.path.join(app_path, 'state')
    log_dir = os.path.join(app_path, 'log')

    create_log_and_state_dir(state_dir, log_dir)

    if options.light:
        LIGHT = True

    if options.debug:
        DEBUG = True
        handler = urlrequest.HTTPSHandler(debuglevel=1)
    else:
        handler = urlrequest.HTTPSHandler()
    opener = urlrequest.build_opener(handler)

    endpoint_config = {'format': cfg.format,
                       'filename': cfg.filename,
                       'state_dir': state_dir,
                       'log_dir': log_dir,
                       'since': options.since}

    if cfg.filename == 'syslog':
        endpoint_config['facility'] = cfg.facility.strip()
        endpoint_config['address'] = cfg.address.strip()
        endpoint_config['socktype'] = cfg.socktype.strip()

    SIEM_LOGGER.addHandler(create_output_handler(endpoint_config))

    for endpoint in tuple_endpoint:
        process_endpoint(endpoint, opener, endpoint_config, token, client)


def process_endpoint(endpoint, opener, endpoint_config, token, client):
    state_file_name = "siem_lastrun_" + endpoint.rsplit('/', 1)[-1] + ".obj"
    state_file_path = os.path.join(endpoint_config['state_dir'], state_file_name)
    if LIGHT and endpoint == ENDPOINT_MAP['event'][0]:
        log("Light mode - not retrieving:%s" % '; '.join(NOISY_EVENTTYPES))

    log("Config endpoint=%s, filename='%s' and format='%s'" %
        (endpoint, endpoint_config['filename'], endpoint_config['format']))
    log("Config state_file='%s' and cwd='%s'" % (state_file_path, os.getcwd()))
    cursor = False
    since = False
    if endpoint_config['since']:  # Run since supplied datetime
        since = endpoint_config['since']
    else:
        try:  # Run since last run (retrieve from state_file)
            with open(state_file_path, 'rb') as f:
                cursor = pickle.load(f)
        except IOError:  # Default to current time
            since = int(calendar.timegm(((datetime.datetime.utcnow() - datetime.timedelta(hours=12)).timetuple())))
            log("No datetime found, defaulting to last 12 hours for results")

    if since is not False:
        log('Retrieving results since: %s' % since)
    else:
        log('Retrieving results starting cursor: %s' % cursor)

    access_token = ''
    if client['client_id'] and client['client_secret']:
        jwt_token = get_sophos_jwt(client['client_id'], client['client_secret'])
        log("jwt_token :: %s" % jwt_token)
        if jwt_token.get('access_token'):
            access_token = jwt_token.get('access_token')
        else:
            log("JWT token not found")
            return

    client['access_token'] = access_token
    results = call_endpoint(opener, endpoint, since, cursor, state_file_path, token, client)

    if endpoint_config['format'] == 'json':
        write_json_format(results)
    elif endpoint_config['format'] == 'keyvalue':
        write_keyvalue_format(results)
    elif endpoint_config['format'] == 'cef':
        write_cef_format(results)
    else:
        write_json_format(results)


def create_output_handler(endpoint_config):
    if endpoint_config['filename'] == 'syslog':
        facility = SYSLOG_FACILITY[endpoint_config['facility']]
        address = endpoint_config['address']
        if ':' in address:
            result = address.split(':')
            host = result[0]
            port = result[1]
            address = (host, int(port))

        socktype = SYSLOG_SOCKTYPE[endpoint_config['socktype']]
        logging_handler = logging.handlers.SysLogHandler(address, facility, socktype)
    elif endpoint_config['filename'] == 'stdout':
        logging_handler = logging.StreamHandler(sys.stdout)
    else:
        logging_handler = logging. \
            FileHandler(os.path.join(endpoint_config['log_dir'], endpoint_config['filename']), 'a', encoding='utf-8')
    return logging_handler


def write_json_format(results):
    for i in results:
        i = remove_null_values(i)
        update_cef_keys(i)
        name_mapping.update_fields(log, i)
        SIEM_LOGGER.info(json.dumps(i, ensure_ascii=False) + u'\n')


def write_keyvalue_format(results):
    for i in results:
        i = remove_null_values(i)
        update_cef_keys(i)
        name_mapping.update_fields(log, i)
        date = i[u'rt']
        # TODO:  Spaces/quotes/semicolons are not escaped here, does it matter?
        events = list('%s="%s";' % (k, v) for k, v in i.items())
        SIEM_LOGGER.info(' '.join([date, ] + events) + u'\n')


def write_cef_format(results):
    for i in results:
        i = remove_null_values(i)
        name_mapping.update_fields(log, i)
        SIEM_LOGGER.info(format_cef(flatten_json(i)) + u'\n')


def create_log_and_state_dir(state_dir, log_dir):
    if not os.path.exists(state_dir):
        try:
            os.makedirs(state_dir)
        except OSError as e:
            log("Failed to create %s, %s" % (state_dir, str(e)))
            sys.exit(1)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError as e:
            log("Failed to create %s, %s" % (log_dir, str(e)))
            sys.exit(1)


def get_sophos_jwt(client_id=None, client_secret=None):
    """Fetch the Sophos JWT access token.

    Get the token by calling Sophos API.

    Arguments:
        client_id {string} -- sophos' client id (default: {None})
        client_secret {string} -- sophos' client secret (default: {None})

    Returns:
        dict -- response containing either of jwt token or error
    """
    
    log("fetching access_token from sophos")
    body = {
        "grant_type": "client_credentials",
        "scope": "token",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    log("body :: %s" % str(body))
    
    try:
        data = urlencode(body).encode("utf-8")
        req = urlrequest.Request(OAUTH2_TOKEN_V2, data)
        response = urlrequest.urlopen(req)

        if response.code == 200:
            response = json.loads(response.read().decode('utf-8'))
            log("response :: %s" % str(response))
            log("jwt :: %s" % response["access_token"])
        else:
            log("Error :: %s" % response)

        return response
    except Exception as e:
        log("Error :: %s" % e)
        return { "reason": e.reason }


def call_endpoint(opener, endpoint, since, cursor, state_file_path, token, client):
    if client['access_token'] and client['x_tenant_id']:
        token_url = OAUTH2_TOKEN_V2
        default_headers = {'Content-Type': 'application/json; charset=utf-8',
                       'Accept': 'application/json',
                       'X-Locale': 'en',
                       'X-Tenant-ID': client['x_tenant_id'],
                       'Authorization': 'Basic ' + client['access_token']
                       }
    else:
        token_url =  token.url
        default_headers = {'Content-Type': 'application/json; charset=utf-8',
                       'Accept': 'application/json',
                       'X-Locale': 'en',
                       'Authorization': token.authorization,
                       'x-api-key': token.api_key}

    params = {
        'limit': 1000
    }
    if not cursor:
        params['from_date'] = since
    else:
        params['cursor'] = cursor
        jitter()

    while True:
        if LIGHT and endpoint == ENDPOINT_MAP['event'][0]:
            types = ','.join(["%s" % t for t in NOISY_EVENTTYPES])
            types = 'exclude_types=' + types
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()]+[types, ])
        else:
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()])
        events_request_url = '%s%s?%s' % (token_url, endpoint, args)
        log("URL: %s" % events_request_url)
        events_request = urlrequest.Request(events_request_url, None, default_headers)

        for k, v in default_headers.items():
            events_request.add_header(k, v)

        events_response = request_url(opener, events_request)
        if DEBUG:
            log("RESPONSE: %s" % events_response)
        events = json.loads(events_response)

        # events looks like this
        # {
        # u'chart_detail': {u'2014-10-01T00:00:00.000Z': 3638},
        # u'event_counts': {u'Event::Endpoint::Compliant': 679,
        # u'events': {}
        # }
        for e in events['items']:
            e[u'datastream'] = EVENT_TYPE if(endpoint == EVENTS_V1) else ALERT_TYPE
            yield e

        store_state(events['next_cursor'], state_file_path)
        if not events['has_more']:
            break
        else:
            params['cursor'] = events['next_cursor']
            params.pop('from_date', None)


def store_state(next_cursor, state_file_path):
    # Store cursor
    log("Next run will retrieve results using cursor %s\n" % next_cursor)
    with open(state_file_path, 'wb') as f:
        pickle.dump(next_cursor, f, protocol=2)


# Flattening JSON objects in Python
# https://medium.com/@amirziai/flattening-json-objects-in-python-f5343c794b10#.37u7axqta
def flatten_json(y):
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def log(s):
    if not QUIET:
        sys.stderr.write('%s\n' % s)


def jitter():
    time.sleep(randint(0, 10))


def request_url(opener, request):
    for i in [1, 2, 3]:  # Some ops we simply retry
        try:
            response = opener.open(request)
        except urlerror.HTTPError as e:
            if e.code in (503, 504, 403, 429):
                log('Error "%s" (code %s) on attempt #%s of 3, retrying' % (e, e.code, i))
                if i < 3:
                    continue
            log('Error during request. Error code: %s, Error message: %s' % (e.code, e.read()))
            raise
        return response.read()


def format_prefix(data):
    # pipe and backslash in header must be escaped
    # escape group with backslash
    return PREFIX_PATTERN.sub(r'\\\1', data)


def format_extension(data):
    # equal sign and backslash in extension value must be escaped
    # escape group with backslash
    if type(data) is str:
        return EXTENSION_PATTERN.sub(r'\\\1', data)
    else:
        return data


def map_severity(severity):
    if severity in SEVERITY_MAP:
        return SEVERITY_MAP[severity]
    else:
        msg = 'The "%s" severity can not be mapped, defaulting to 0' % severity
        log(msg)
        return SEVERITY_MAP['none']


def extract_prefix_fields(data):
    # extract prefix fields and remove those from data dictionary
    name_field = CEF_MAPPING['name']
    device_event_class_id_field = CEF_MAPPING['device_event_class_id']
    severity_field = CEF_MAPPING['severity']

    name = data.get(name_field, MISSING_VALUE)
    name = format_prefix(name)
    data.pop(name_field, None)

    device_event_class_id = data.get(device_event_class_id_field, MISSING_VALUE)
    device_event_class_id = format_prefix(device_event_class_id)
    data.pop(device_event_class_id_field, None)

    severity = data.get(severity_field, MISSING_VALUE)
    severity = map_severity(severity)
    data.pop(severity_field, None)

    fields = {'name': name,
              'device_event_class_id': device_event_class_id,
              'severity': severity,
              'version': CEF_CONFIG['cef.version'],
              'device_vendor': CEF_CONFIG['cef.device_vendor'],
              'device_version': CEF_CONFIG['cef.device_version'],
              'device_product': CEF_CONFIG['cef.device_product']}
    return fields


def update_cef_keys(data):
    # Replace if there is a mapped CEF key
    for key, value in list(data.items()):
        new_key = CEF_MAPPING.get(key, key)
        if new_key == key:
            continue
        data[new_key] = value
        del data[key]


def format_cef(data):
    fields = extract_prefix_fields(data)
    msg = CEF_FORMAT % fields

    update_cef_keys(data)
    for index, (key, value) in enumerate(data.items()):
        value = format_extension(value)
        if index > 0:
            msg += ' %s=%s' % (key, value)
        else:
            msg += '%s=%s' % (key, value)
    return msg


def remove_null_values(data):
    return {k: v for k, v in data.items() if v is not None}


if __name__ == "__main__":
    main()
