import csv


def load_log_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        list_logs = [line for line in csv.reader(file)]
    return list_logs


def external_ip_extraction(list_logs):
    external_ip = [ip[1] for ip in list_logs if not ip[1].startswith(('192.168', '10'))]
    return external_ip


def sensitive_port_filtering(list_logs):
    sensitive_ports = [port for port in list_logs if port[3].startswith(('22', '23', '3389'))]
    return sensitive_ports


def filter_by_size(list_logs):
    filter_size = [size for size in list_logs if int(size[-1]) > 5000]
    return filter_size
