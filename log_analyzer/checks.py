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