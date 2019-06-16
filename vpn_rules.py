import vpn_index

indexes = vpn_index.build_indexes()


def same_user_different_geo():
    matches = []

    for user in indexes.users:
        for event in indexes.users[user]:
            matched_events = [event]
            event_time = indexes.timestamps.get(event)
            for ip in indexes.ips:
                if event in indexes.ips[ip]:
                    remote_ip = ip
                    country_code = indexes.ip2country.get(remote_ip)
            for other_event in indexes.users[user]:
                if other_event != event:
                    other_event_time = indexes.timestamps.get(other_event)

                    for ip in indexes.ips:
                        if other_event in indexes.ips[ip]:
                            other_remote_ip = ip
                            other_country_code = indexes.ip2country.get(other_remote_ip)

                    if country_code != other_country_code:
                        if abs(other_event_time - event_time) <= 3600:
                            matched_events.append(other_event)

            if len(matched_events) > 1:
                match_count = 0
                for match in matches:
                    if len(match) == len(matched_events):
                        for event in matched_events:
                            if event in match:
                                match_count += 1
                if match_count != len(matched_events):
                    matches.append(matched_events)

    return matches



        

