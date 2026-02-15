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