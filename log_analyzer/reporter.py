from reader import load_log_func, load_log_gen
from checks import check_row_suspicions, process_all_logs_gen, suspicions_checks
from analyzer import ip_suspicions


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


def suspicions_with_details_gen(list_logs):
    for log in list_logs:
        yield log, check_row_suspicions(log)


def sum_suspicious_rows(line_details):
    return sum(1 for log in line_details if len(log[1]) > 0)


lines = load_log_gen(r'./network_traffic.log') # generator
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



# def generate_report(suspicious_dict):
#     global total_lines_read, total_suspicious_lines, suspicious_counts
    
#     report = "=======================================\n"
#     report += "       Suspicious Traffic Report\n"
#     report += "=======================================\n\n"
    
#     report += "General Statistics:\n"
#     report += f"- Lines read: {total_lines_read}\n"
#     report += f"- Suspicious lines: {total_suspicious_lines}\n"
    
#     for name, count in suspicious_counts.items():
#         report += f"- {name}: {count}\n"
        
#     report += "\nHigh Risk IPs (3+ threats):\n"
    
#     for ip, threats in suspicious_dict.items():
#         if len(threats) >= 3:
#             report += f"- {ip}: {', '.join(threats)}\n"
            
#     report += "\nOther Suspicious IPs:\n"
    
#     for ip, threats in suspicious_dict.items():
#         if len(threats) < 3:
#             report += f"- {ip}: {', '.join(threats)}\n"
            
#     return report


def generate_report(suspicious_dict):
    global total_lines_read, total_suspicious_lines, suspicious_counts

    stats_section = [
        "\n=======================================",
        "        SUSPICIOUS TRAFFIC REPORT",
        "=======================================",
        "\nGeneral Statistics:",
        f"- Total lines read: {total_lines_read:,}",
        f"- Total suspicious lines: {total_suspicious_lines:,}"
    ]
    
    for name, count in suspicious_counts.items():
        stats_section.append(f"- {name}: {count:,}")

    high_risk = []
    other_suspicious = []
    
    for ip, threats in suspicious_dict.items():
        entry = f"- {ip}: {', '.join(threats)}"
        if len(threats) >= 3:
            high_risk.append(entry)
        else:
            other_suspicious.append(entry)

    report_body = stats_section + \
                  ["\n--- High Risk IPs (3+ threats):\n"] + high_risk + \
                  ["\n--- Other Suspicious IPs:\n"] + other_suspicious

    return "\n".join(report_body)