from config import threat_rules


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
    suspicions = {
        ip: [
            name 
            for name, check_func in threat_rules.items()
            if any(check_func(log) for log in list_logs if log[1] == ip)
        ] 
        for ip in unique_ips
    }
    
    return suspicions