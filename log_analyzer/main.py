import reporter as rep
from config import save_report


def menu():
    print(f"\
          1. Viewing the log report     |   2. Viewing port protocol\n\
          3. Filtering by external IP   |   4. Filtering by suspicious IP\n\
          5. Per-ip requests            |   6. Filter by 5+ MB package\n\
          7. Night traffic filtering    |   8. View full report\n\
          9. Export a report            |   10. exit"
          )
    while True:
        user_choise = input("\n\tSelect a desired request (1-10):  ")
        if user_choise in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']:
            return user_choise
        print("Select an action request between 1 and 10 only.")
        


def main():
    print(f"\n\t\t< Welcome to the network traffic analysis system >\n\n")
    func_actions = {
        '1' : rep.print_log,
        '2' : rep.print_ports,
        '3' : rep.print_external_ips,
        '4' : rep.print_suspicious,
        '5' : rep.print_req_count,
        '6' : rep.print_by_packet,
        '7' : rep.print_night_traffic,
        '8' : rep.generate_report,
        '9' : save_report
        }

    show_menu = True
    while show_menu:
        action = menu()
        if action == "8":
            print(func_actions[action](rep.log_analyze(rep.path)))
        elif action == "9":
            func_actions[action](func_actions['8'](rep.log_analyze(rep.path)), './security_report.txt')
            print("\n\tThe report was successfully updated!")
        elif action == "10":
            exit("\n\tGoodbye..")
        else:
            func_actions[action]()

        while True:
            again = input("\n\tDo you want to perform another action? (y/n):  ")
            if again not in ['y', 'n']:
                print("\tPlease select y / n.")
            elif again == "n":
                show_menu = False
                print("\n\tGoodbye..")
                break
            else:
                break


if __name__ == "__main__":
    main()