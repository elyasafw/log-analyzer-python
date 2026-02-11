import csv


def load_log_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        list_logs = [line for line in csv.reader(file)]
    return list_logs


def external_ip_extraction(list_logs):
    external_ip = [ip[1] for ip in list_logs if not ip[1].startswith(('192.168', '10'))]
    return external_ip