from reader import load_log_func, load_log_gen, external_ip_extraction, filter_by_size
from checks import check_row_suspicions, process_all_logs_gen, suspicions_checks
from analyzer import ip_suspicions, port_to_protocol, req_count_by_ip
from pathlib import Path

path = Path(r'./network_traffic.log')


def extract_hours():
    logs = load_log_func(path)
    
    hours_list = list(map(
        lambda log_line: int(log_line[0][11:13]),
        logs
        ))

    return hours_list


def package_size_conversion():
    logs = load_log_func(path)

    package_size = list(map(
        lambda package: float(int(package[-1]) // 1024),
        logs
        ))

    return package_size


def filter_by_port():
    logs = load_log_func(path)

    sensitive_lines = list(filter(
        lambda line: suspicions_checks["PORT_SENSITIVE"](line),
        logs
        ))

    return sensitive_lines


def filter_night_activity():
    logs = load_log_func(path)

    night_logs = list(filter(
        lambda log: suspicions_checks["ACTIVITY_NIGHT"](log),
        logs
        ))

    return night_logs


def suspicions_with_details_gen(list_logs):
    for log in list_logs:
        yield log, check_row_suspicions(log)


def sum_suspicious_rows(line_details):
    return sum(1 for log in line_details if len(log[1]) > 0)


lines = load_log_gen(path) # generator
suspicious = process_all_logs_gen(lines) # generator
detailed = suspicions_with_details_gen(suspicious) # generator

count = sum_suspicious_rows(detailed)
# print(f"Total suspicious: {count}")


total_lines_read = 0
total_suspicious_lines = 0
suspicious_counts = {
    "EXTERNAL_IP": 0,
    "PORT_SENSITIVE": 0,
    "PACKET_LARGE": 0,
    "ACTIVITY_NIGHT": 0
}

def update_statistics(found_suspicion):
    global total_lines_read, total_suspicious_lines, suspicious_counts
    
    total_lines_read += 1

    if found_suspicion:
        total_suspicious_lines += 1
        for suspicion in found_suspicion:
            if suspicion in suspicious_counts:
                suspicious_counts[suspicion] += 1


def log_analyze(file_path):
    list_logs = list(load_log_gen(file_path)) 
    
    suspicions_dict = ip_suspicions(list_logs)
    
    for log in list_logs:
        current_suspicion = check_row_suspicions(log) 
        update_statistics(current_suspicion)
        
    return suspicions_dict


def generate_report(suspicious_dict):
    global total_lines_read, total_suspicious_lines, suspicious_counts

    stats_section = [
        "\n\n\t=======================================",
        "        \tSUSPICIOUS TRAFFIC REPORT",
        "\t=======================================",
        "\n\tGeneral Statistics:",
        f"\t- Total lines read: {total_lines_read:,}",
        f"\t- Total suspicious lines: {total_suspicious_lines:,}"
    ]
    
    for name, count in suspicious_counts.items():
        stats_section.append(f"\t- {name}: {count:,}")

    high_risk = []
    other_suspicious = []
    
    for ip, threats in suspicious_dict.items():
        entry = f"\t- {ip}: {', '.join(threats)}"
        if len(threats) >= 3:
            high_risk.append(entry)
        else:
            other_suspicious.append(entry)

    report_body = stats_section + \
                  ["\n\t--- High Risk IPs (3+ threats):\n"] + high_risk + \
                  ["\n\t--- Other Suspicious IPs:\n"] + other_suspicious

    return "\n".join(report_body)


def print_log():
    print("\n\n\t--- Log report ---\n")
    count = 0
    for i in sorted(load_log_gen(path), key=lambda x: x[0]):
        count += 1
        print(f"\t-  {" | ".join(i)}")
    print(f"\n\tTotal log lines:: {count}")


def print_external_ips():
    print("\n\n\t--- List of external IP addresses ---\n")
    count = 0
    for i in sorted(external_ip_extraction(load_log_gen(path))):
        count += 1
        print(f"\t-  {i}")
    print(f"\n\tTotal external IP addresses found: {count}")


def print_suspicious():
    print("\n\n\t--- List of suspicious IP addresses ---\n")
    count = 0
    for k, v in sorted(ip_suspicions(load_log_func(path)).items(), key=lambda x: len(x[1])):
        count += 1
        print(f"\t-  {k} :  {" | ".join(v)}")
    print(f"\n\tTotal suspicious IP addresses found: {count}")


def print_ports():
    print("\n\n\t--- Port list ---\n")
    count = 0
    for k, v in port_to_protocol(load_log_gen(path)).items():
        count += 1
        print(f"\t-  {k} :  {v}")
    print(f"\n\tTotal ports found: {count}")


def print_night_traffic():
    print("\n\n\t--- Traffic list at: 12 pm to 6 am ---\n")
    count = 0
    for i in sorted(filter_night_activity(), key=lambda x: x[0]):
        count += 1
        print(f"\t-  {" | ".join(i)}")
    print(f"\n\tTotal night traffic found: {count}")


def print_req_count():
    print("\n\n\t--- List of total requests by IP ---\n")
    count = 0
    for k, v in sorted(req_count_by_ip(load_log_gen(path)).items(), key=lambda x: x[1]):
        count += 1
        print(f"\t-  {k} :  {v}")
    print(f"\n\tTotal IP addresses: {count}")


def print_by_packet():
    print("\n\n\t--- Logs with a package of 5 MB or more ---\n")
    count = 0
    for i in sorted(filter_by_size(load_log_gen(path)), key=lambda x: int(x[5])):
        count += 1
        print(f"\t-  {" | ".join(i)}")
    print(f"\n\tTotal logs found:: {count}")