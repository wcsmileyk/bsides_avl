import os
import datetime
from collections import Counter, namedtuple
import time
import json

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


def ip_and_code(event, indexes):
    for ip in indexes.ips:
        if event in indexes.ips[ip]:
            return ip, indexes.ip2country.get(ip)


def same_user_different_geo():
    matches = []

    for user in indexes.users:
        matched_events = []
        for event in indexes.users[user]:
            event_time = indexes.timestamps.get(event)
            remote_ip, country_code = ip_and_code(event, indexes)

            for event2 in indexes.users[user]:
                if event2 != event:
                    event2_time = indexes.timestamps.get(event2)

                    event2_r_ip, event2_country_code = ip_and_code(event2, indexes)

                    if country_code != event2_country_code:
                        if abs(event2_time - event_time) <= 3600:
                            if event not in matched_events:
                                matched_events.append(event)
                            if event2 not in matched_events:
                                matched_events.append(event2)

            if len(matched_events) > 1 and len(matches) > 0:
                for match in matches:
                    if not Counter(match) == Counter(matched_events):
                        matches.append(matched_events)
            elif len(matched_events) > 1:
                matches.append(matched_events)
    return matches


def get_event(event_id):
    for f in os.listdir(JSON_DIR):
        events = get_events(f)
        if event_id in events:
            return events[event_id]


def alienvault_ip_lookup(ip_addr):
    api_token = os.environ.get('ALIENTVAULT')
    url = f'https://otx.alienvault.com:443/api/v1/indicators/IPv4/{ip_addr}'
    headers = {'X-OTX-API-KEY': api_token, 'Accept': 'application/json', 'Content-Type': 'application/json'}

    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        threat = r.json()
    else:
        return None

    pulse_info = threat.get('pulse_info')
    if pulse_info:
        pulses = pulse_info.get('pulses')
        tags = [tag for pulse in pulses for tag in pulse.get('tags')]
    else:
        tags = None

    desc = threat['base_indicator'].get('description')
    reputation = threat.get('reputation')

    return {'description': desc, 'tags': tags, 'reputation': reputation}


if __name__ == '__main__':
    indexes = build_indexes()

    poss_compromises = same_user_different_geo()

    headers = 'time | user | country code | remote ip | alienvault desc | alienvault tags | alienvault reputation'
    print(headers)
    print ('-' * len(headers))

    for compromise in poss_compromises:
        for event_id in compromise:
            full_event = get_event(event_id)
            event_time = datetime.datetime.fromtimestamp(full_event['event_time'])
            user = full_event['remote_user']
            ip = full_event['remote_ip']
            country_code = indexes.ip2country[ip]

            alv_rep = alienvault_ip_lookup(ip)

            print(f'{event_time} | {user} | {country_code} | {ip} | {alv_rep["description"]} | {alv_rep["tags"]} | {alv_rep["reputation"]}')








        

