#!/usr/bin/env python

# Copyright 2016 Sophos Limited
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
req_version = (2, 7, 9)
cur_version = sys.version_info
if cur_version >= (3, 0):
    sys.stderr.write("Python 3.x is not supported. %s")
    sys.exit(1)
elif cur_version < req_version:
    sys.stderr.write("Python 2.7.9+ is supported.")
    sys.exit(1)
import calendar
import ConfigParser
import datetime
import json
import logging
import logging.handlers
import os
import pickle
import re
import socket
import time
import urllib2
from optparse import OptionParser
from random import randint

try:
    import syslog

    SYSLOG_FACILITY = {'auth': syslog.LOG_AUTH,
                       'cron': syslog.LOG_CRON,
                       'daemon': syslog.LOG_DAEMON,
                       'kern': syslog.LOG_KERN,
                       'lpr': syslog.LOG_LPR,
                       'mail': syslog.LOG_MAIL,
                       'news': syslog.LOG_NEWS,
                       'syslog': syslog.LOG_SYSLOG,
                       'user': syslog.LOG_USER,
                       'uucp': syslog.LOG_UUCP,
                       'local0': syslog.LOG_LOCAL0,
                       'local1': syslog.LOG_LOCAL1,
                       'local2': syslog.LOG_LOCAL2,
                       'local3': syslog.LOG_LOCAL3,
                       'local4': syslog.LOG_LOCAL4,
                       'local5': syslog.LOG_LOCAL5,
                       'local6': syslog.LOG_LOCAL6,
                       'local7': syslog.LOG_LOCAL7}

    SYSLOG_SOCKTYPE = {'udp': socket.SOCK_DGRAM,
                       'tcp': socket.SOCK_STREAM}

except ImportError:
    syslog = None


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

NOISY_EVENTTYPES = ['Event::Endpoint::NonCompliant',
                    'Event::Endpoint::Compliant',
                    'Event::Endpoint::Device::AlertedOnly',
                    'Event::Endpoint::UpdateFailure',
                    'Event::Endpoint::SavScanComplete',
                    'Event::Endpoint::Application::Allowed',
                    'Event::Endpoint::UpdateSuccess',
                    'Event::Endpoint::WebControlViolation',
                    'Event::Endpoint::WebFilteringBlocked']

ENDPOINT_MAP = {'event': ['/siem/v1/events'],
                'alert': ['/siem/v1/alerts'],
                'all': ['/siem/v1/events', '/siem/v1/alerts']}

CEF_CONFIG = {'cef.version': '0', 'cef.device_vendor': 'sophos',
              'cef.device_product': 'sophos central', 'cef.device_version': 1.0}

# CEF format from https://www.protect724.hpe.com/docs/DOC-1072
CEF_FORMAT = ('CEF:%(version)s|%(device_vendor)s|%(device_product)s|'
              '%(device_version)s|%(device_event_class_id)s|%(name)s|%(severity)s|')


def main():
    global NOISY_EVENTTYPES, LIGHT, DEBUG, CEF_MAPPING, NAME_MAPPING, QUIET

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
    config = ConfigParser.ConfigParser()
    config.read(options.config)

    try:
        token_info = config.get('login', 'token_info')
        token_list = token_info.split(',')
        url = token_list[0].split(': ')[1]
        api_key = token_list[1].strip()
        authorization = token_list[2].strip()
        log("Config loaded, retrieving results for '%s'" % api_key)
        log("Config retrieving results for '%s'" % authorization)
    except:
        e = sys.exc_info()[0]
        log("Failed to parse token_info in config file, %s" % e)
        sys.exit(1)

    if config.get('login', 'endpoint') in ENDPOINT_MAP:
        tuple_endpoint = ENDPOINT_MAP[config.get('login', 'endpoint')]
    else:
        tuple_endpoint = ENDPOINT_MAP[DEFAULT_ENDPOINT]

    log_format = config.get('login', 'format')
    filename = config.get('login', 'filename')
    if filename == 'syslog':
        if syslog is None:
            log('syslog is not supported on this platform')
            sys.exit(1)

    CEF_MAPPING = read_cef_mapping_file(app_path)
    NAME_MAPPING = read_name_mapping_file(app_path)

    state_dir = os.path.join(app_path, 'state')
    log_dir = os.path.join(app_path, 'log')

    create_log_and_state_dir(state_dir, log_dir)

    if options.light:
        LIGHT = True

    if options.debug:
        DEBUG = True
        handler = urllib2.HTTPSHandler(debuglevel=1)
    else:
        handler = urllib2.HTTPSHandler()
    opener = urllib2.build_opener(handler)

    creds = {'url': url,
             'api_key': api_key,
             'authorization': authorization
             }

    endpoint_config = {'format': log_format,
                       'filename': filename,
                       'state_dir': state_dir,
                       'log_dir': log_dir,
                       'since': options.since}
    if filename == 'syslog':
        endpoint_config['facility'] = (config.get('login', 'facility')).strip()
        endpoint_config['address'] = config.get('login', 'address')
        endpoint_config['socktype'] = (config.get('login', 'socktype')).strip()

    for endpoint in tuple_endpoint:
        process_endpoint(endpoint, opener, endpoint_config, creds)


def process_endpoint(endpoint, opener, endpoint_config, creds):
    state_file_name = "siem_lastrun_" + endpoint.rsplit('/', 1)[-1] + ".obj"
    state_file_path = os.path.join(endpoint_config['state_dir'], state_file_name)
    if LIGHT and endpoint == ENDPOINT_MAP['event']:
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
            with open(state_file_path, 'r') as f:
                cursor = pickle.load(f)
        except IOError:  # Default to current time
            since = int(calendar.timegm(((datetime.datetime.utcnow() - datetime.timedelta(hours=12)).timetuple())))
            log("No datetime found, defaulting to last 12 hours for results")

    if since is not False:
        log('Retrieving results since: %s' % since)
    else:
        log('Retrieving results starting cursor: %s' % cursor)

    siem_logger = logging.getLogger('SIEM')
    logging.basicConfig(format='%(message)s')
    siem_logger.setLevel(logging.INFO)
    siem_logger.propagate = False
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
        logging_handler = logging.\
            FileHandler(os.path.join(endpoint_config['log_dir'], endpoint_config['filename']), 'a', encoding='utf-8')
    siem_logger.addHandler(logging_handler)

    results = call_endpoint(opener, endpoint, since, cursor, state_file_path, creds)

    if endpoint_config['format'] == 'json':
        write_json_format(results, siem_logger)
    elif endpoint_config['format'] == 'keyvalue':
        write_keyvalue_format(results, siem_logger)
    elif endpoint_config['format'] == 'cef':
        write_cef_format(results, siem_logger)
    else:
        write_json_format(results, siem_logger)


def write_json_format(results, siem_logger):
    for i in results:
        i = remove_null_values(i)
        update_cef_keys(i)
        update_name_field(i)
        siem_logger.info(json.dumps(i, ensure_ascii=False) + u'\n')


def write_keyvalue_format(results, siem_logger):
    for i in results:
        i = remove_null_values(i)
        update_cef_keys(i)
        update_name_field(i)
        date = i[u'rt']
        events = list('%s="%s";' % (k, v) for k, v in i.items())
        siem_logger.info(' '.join([date, ] + events) + u'\n')


# Split 'name' field into multiple fields based on regex and field names specified in the name_mapping.txt
# Original 'name' field is replaced with the first value returned by regex used for splitting 'name' field.
def update_name_field(data):
    if u'description' in data.keys():
        data[u'name'] = data[u'description']
    if data[u'type'] in NAME_MAPPING:
        try:
            # name_list has a compiled regex followed by new field names in which name field needs to be split into.
            name_list = NAME_MAPPING[data[u'type']]
            prog_regex = name_list[0]
            result = prog_regex.findall(data[u'name'])
            if len(result) == len(name_list) - 1:
                # update name with the first value for CEF as its name is a required header in CEF
                data[u'name'] = result[0]
                for idx, item in enumerate(name_list[1:]):
                    data[item] = result[idx]

        except:
            e = sys.exc_info()[0]
            log("Failed to split name field for event type %s, error %s" % (data[u'type'], e))


def write_cef_format(results, siem_logger):
    for i in results:
        i = remove_null_values(i)
        update_name_field(i)
        siem_logger.info(format_cef(flatten_json(i)) + u'\n')


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


def call_endpoint(opener, endpoint, since, cursor, state_file_path, creds):
    default_headers = {'Content-Type': 'application/json; charset=utf-8',
                       'Accept': 'application/json',
                       'X-Locale': 'en',
                       'Authorization': creds['authorization'].split(":")[1],
                       'x-api-key': creds['api_key'].split(":")[1]}

    params = {
        'limit': 1000
    }
    if not cursor:
        params['from_date'] = since
    else:
        params['cursor'] = cursor
        jitter()

    while True:
        if LIGHT and endpoint == ENDPOINT_MAP['event']:
            types = ','.join(["%s" % t for t in NOISY_EVENTTYPES])
            types = 'exclude_types=' + types
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()]+[types, ])
        else:
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()])
        events_request_url = '%s%s?%s' % (creds['url'], endpoint, args)
        log("URL: %s" % events_request_url)
        events_request = urllib2.Request(events_request_url, None, default_headers)

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
        pickle.dump(next_cursor, f)


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


def read_cef_mapping_file(app_path):
    cef_mapping = {}
    with open(os.path.join(app_path, "siem_cef_mapping.txt")) as f:
        for line in f:
            if line.startswith('#') or line == "\n":
                pass
            else:
                (key, val) = line.split()
                cef_mapping[key] = val
    return cef_mapping


def read_name_mapping_file(app_path):
    name_mapping = {}
    with open(os.path.join(app_path, "name_mapping.txt")) as f:
        for line in f:
            if line.startswith('#') or line == "\n":
                pass
            else:
                words = line.split()
                name_list = list(words[2:])
                name_list.insert(0, re.compile(words[1]))
                name_mapping[words[0]] = name_list
    return name_mapping


def jitter():
    time.sleep(randint(0, 10))


def request_url(opener, request):
    for i in [1, 2, 3]:  # Some ops we simply retry
        try:
            response = opener.open(request)
        except urllib2.HTTPError as e:
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
    return EXTENSION_PATTERN.sub(r'\\\1', data)


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
