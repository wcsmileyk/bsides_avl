from dateutil import parser
from collections import namedtuple
import re


def parse_syslog(log_message, header_fields=4, deliminator=' '):
    Syslog = namedtuple('Syslog', ['log_time', 'log_source', 'application', 'message_body'])
    
    dt, log_source, log_app, message_body = log_message.split(' ', 3)
    log_time = parser.parse(dt)
    return Syslog(log_time=log_time, 
                  log_source=log_source, 
                  application=log_app, 
                  message_body=message_body)


def parse_fw(fw_message):
    msg_dict = {'additional_data': []}
    for pair in fw_message.split(' '):
        try:
            k, v = pair.split('=', 1)
            msg_dict[k] = v
        except ValueError:
            msg_dict['additional_data'].append(pair)
    return msg_dict


def get_user_ovpn(ovpn_message):
    user_pattern = re.compile('\w+/(\d{1,3}\.){3}\d{1,3}')

    return user_pattern.search(ovpn_message)


def parse_ovpn(ovpn_message):
    user_pattern = re.compile('(\w+)/((\d{1,3}\.){3}\d{1,3})')
    date_pattern = re.compile('(\w{3}\s+\w{3}\s+\d{1,2}\s+(\d{1,2}:){2}\d{1,2}\s+\d{4})\s')

    user_ip = user_pattern.search(ovpn_message)
    user = user_ip.group(1)
    ip_addr = user_ip.group(2)
    date_search = date_pattern.search(ovpn_message)
    event_time = parser.parse(date_search.group(1))

    return {'remote_user': user, 'remote_ip': ip_addr, 'event_time': event_time}




