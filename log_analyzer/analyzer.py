from checks import suspicions_checks


def req_count_count_by_ip(list_logs):
    all_ips = [
        row[1] for row in list_logs
        ]
    req_ips = {
        ip: all_ips.count(ip) for ip in set(all_ips)
        }

    return req_ips


def port_to_protocol(list_logs):
    protocol = {
        port[3] : port[4] for port in list_logs
        }

    return protocol


def ip_suspicions(list_logs):
    unique_ips = {
        log[1] for log in list_logs
        }
    suspicions_dict = {
        ip : [
            suspicions 
            for suspicions, check_func in suspicions_checks.items()
            if any(check_func(log) for log in list_logs if log[1] == ip)
        ] 
        for ip in unique_ips
    }
    
    return suspicions_dict


def filtering_suspicions(suspicions_dict):
    more_2_suspicions = {
        ip :
        suspicions_dict[ip] for ip in suspicions_dict if len(suspicions_dict[ip]) > 2
        }

    return more_2_suspicions