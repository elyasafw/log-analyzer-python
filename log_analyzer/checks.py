from reader import load_log_gen, load_log_func


suspicions_checks = {
    "EXTERNAL_IP":
        lambda log: not log[1].startswith(('192.168', '10.')),
    "PORT_SENSITIVE":
        lambda log: log[3] in ['22', '23', '3389'],
    "PACKET_LARGE":
        lambda log: int(log[-1]) > 5000,
    "ACTIVITY_NIGHT":
        lambda log: 0 <= int(log[0][11:13]) < 6
    }


def check_row_suspicions(row):
    passed_checks = filter(
        lambda item: item[1](row),
        suspicions_checks.items()
        )
    suspicion = [
        item[0] for item in passed_checks
        ]
    
    return suspicion


#function
def process_all_logs_func(list_logs):
    suspicious_only = list(filter(lambda suspicion: len(suspicion) > 0, map(lambda row: check_row_suspicions(row), list_logs)))
    
    return suspicious_only


#generator
def process_all_logs_gen(list_logs):
    for log in list_logs:
        if len(check_row_suspicions(log)) > 0:
            yield log