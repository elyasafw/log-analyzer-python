from reader import load_log_file


def extract_hours():
    logs = load_log_file(r'./network_traffic.log')
    
    hours_list = list(map(
        lambda log_line: int(log_line[0][11:13]),
        logs
        ))

    return hours_list


def package_size_conversion():
    logs = load_log_file(r'./network_traffic.log')

    package_size = list(map(
        lambda package: float(int(package[-1]) // 1024),
        logs
        ))

    return package_size