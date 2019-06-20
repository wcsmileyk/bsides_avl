from dateutil import parser
import re
import os
import sys
import hashlib
import json
import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def parse_syslog(log_message, header_fields=4, deliminator=' '):

    dt, log_source, log_app, message_body = log_message.split(' ', 3)
    log_app_map = {'sshd': 'ssh', 'openvpnas': 'vpn', 'kernel': 'firewall'}

    for app_name in log_app_map:
        if log_app.startswith(app_name):
            app = log_app_map[app_name]
            break
        else:
            app = log_app

    log_time = parser.parse(dt)
    timestamp = datetime.datetime.timestamp(log_time)

    return {'log_source_time': timestamp, 'log_source': log_source, 'app': app, 'message': message_body}


def parse_fw(fw_message):
    msg_dict = {'additional_data': []}
    for pair in fw_message.split(' '):
        try:
            k, v = pair.split('=', 1)
            msg_dict[k] = v
        except ValueError:
            msg_dict['additional_data'].append(pair)
    return msg_dict


def parse_ovpn(ovpn_message):
    # For now let's just get the IP assignment, that is post success and cleans things up a bit. This can be expanded later
    if 'primary virtual IP' not in ovpn_message:
        return None

    user_pattern = re.compile('(\w+)/((\d{1,3}\.){3}\d{1,3})')
    date_pattern = re.compile('(\w{3}\s+\w{3}\s+\d{1,2}\s+(\d{1,2}:){2}\d{1,2}\s+\d{4})\s')

    user_ip = user_pattern.search(ovpn_message)
    if user_ip:
        user = user_ip.group(1)
        ip_addr = user_ip.group(2)
        date_search = date_pattern.search(ovpn_message)
        event_time = parser.parse(date_search.group(1))
        event_timestamp = datetime.datetime.timestamp(event_time)

        return {'remote_user': user, 'remote_ip': ip_addr, 'event_time': event_timestamp}


def make_json_dir(json_dir):
    if not os.path.isdir(json_dir):
        os.mkdir(json_dir)
    return True


def parse_message(app, syslog_dict):
    parse_funcs = {'firewall': parse_fw, 'vpn': parse_ovpn}
    msg = syslog_dict['message']

    try:
        parse_func = parse_funcs[app]
        parsed_message = parse_func(msg)
        for k,v in parsed_message.items():
            syslog_dict[k] = v
    except (AttributeError, KeyError):
        pass

    return syslog_dict


def get_log_hash(log):
    log_hash = hashlib.md5()
    log_hash.update(json.dumps(log).encode('utf-8'))
    return log_hash.hexdigest()


def parse_line(line):
    syslog = parse_syslog(line)
    parsed_log = parse_message(syslog['app'], syslog)
    log_id = get_log_hash(parsed_log)
    return log_id, parsed_log


def build_json(fp):
    events = []

    with open(fp, 'r') as logfile:
        count = 0
        event_block = {}
        for line in logfile:
            log_id, log = parse_line(line)
            event_block[log_id] = log
            count += 1

            if count == 4999:
                events.append(event_block)
                event_block = {}
                count = 0
        events.append(event_block)
    return events


def write_json(json_dir, events):
    dt = datetime.datetime.now()
    seconds = (dt.hour + dt.minute) * 60 + dt.second
    file_name = f"{dt.strftime('%Y%m%d')}_{seconds}.{dt.microsecond}"
    fp = os.path.join(json_dir, file_name)

    with open(fp, 'w') as jsonfile:
        json.dump(events, jsonfile)


def main(log_file):
    json_dir = os.path.join(BASE_DIR, 'json')
    make_json_dir(json_dir)

    events = build_json(log_file)
    for event_block in events:
        write_json(json_dir, event_block)


if __name__ == '__main__':
    log_dir = os.path.join(BASE_DIR, 'logs')
    log_files = ['openvpnas.log',
                 'firewall.log',]

    log_paths = [os.path.join(log_dir, f) for f in log_files]

    for log_file in log_paths:
        main(log_file)
