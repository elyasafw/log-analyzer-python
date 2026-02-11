import csv


def load_log_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        list_logs = [line for line in csv.reader(file)]
    return list_logs