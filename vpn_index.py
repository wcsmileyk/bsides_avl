import os
import json
from collections import namedtuple
import time

import requests

JSON_DIR = os.path.abspath('json')
VpnIndex = namedtuple('VpnIndex', ['users', 'ips', 'timestamps', 'ip2country'])


def get_ip_country(ip_addr):
    url = f'http://ip-api.com/json/{ip_addr}'
    r = requests.get(url)

    if r.status_code == 200:
        ip_data = r.json()
        return ip_data['countryCode']
    else:
        return None


def dlist_append(d, k, v):
    if not d.get(k):
        d[k] = [v]
    else:
        d[k].append(v)


def get_events(f):
    with open(os.path.join(JSON_DIR, f), 'r') as logfile:
        events = json.load(logfile)
    return events


def update_indexes(indx, key, data, timestamp, time_index):
    dlist_append(indx, key, data)
    time_index[data] = timestamp


def index_events(events):
    remote_ips = {}
    remote_users = {}
    vpn_user_timestamps = {}
    ip_country = {}

    start_time = time.time()
    call_count = 0

    for event_id, data in events.items():
        if data['app'] == 'vpn':
            user = data.get('remote_user')
            remote_ip = data.get('remote_ip')

            if user:
                update_indexes(remote_users, user, event_id, data['event_time'], vpn_user_timestamps)
            if remote_ip:
                if not ip_country.get(remote_ip):
                    if call_count == 145 and time.time() - start_time <= 60:
                        time.sleep(60 - (time.time() - start_time))
                        start_time = time.time()
                        call_count = 0
                    country = get_ip_country(remote_ip)
                    if country:
                        ip_country[remote_ip] = country
                    call_count += 1
                update_indexes(remote_ips, remote_ip, event_id, data['event_time'], vpn_user_timestamps)

    return VpnIndex(users=remote_users, ips=remote_ips, timestamps=vpn_user_timestamps, ip2country=ip_country)


def build_indexes():
    user_index = {}
    ip_index = {}
    time_index = {}
    ip_country = {}
    for f in os.listdir(JSON_DIR):
        events = get_events(f)
        indexes = index_events(events)
        user_index.update(**indexes.users)
        ip_index.update(**indexes.ips)
        time_index.update(**indexes.timestamps)
        ip_country.update(**indexes.ip2country)

    return VpnIndex(users=user_index, ips=ip_index, timestamps=time_index, ip2country=ip_country)
