from reader import load_log_func
from checks import suspicions_checks


def extract_hours():
    logs = load_log_func(r'./network_traffic.log')
    
    hours_list = list(map(
        lambda log_line: int(log_line[0][11:13]),
        logs
        ))

    return hours_list


def package_size_conversion():
    logs = load_log_func(r'./network_traffic.log')

    package_size = list(map(
        lambda package: float(int(package[-1]) // 1024),
        logs
        ))

    return package_size


def filter_by_port():
    logs = load_log_func(r'./network_traffic.log')

    sensitive_lines = list(filter(
        lambda line: suspicions_checks["PORT_SENSITIVE"](line),
        logs
        ))

    return sensitive_lines


def filter_night_activity():
    logs = load_log_func(r'./network_traffic.log')

    night_logs = list(filter(
        lambda log: suspicions_checks["ACTIVITY_NIGHT"](log),
        logs
        ))

    return night_logs


