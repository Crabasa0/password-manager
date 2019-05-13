#
#
#   The interface for the p@ssword manager. Implementations handled in
#   another module.
#
import getpass
import impl

def login_menu():
    print('Hello, ' + getpass.getuser())
    good_login = False
    while not good_login:
        p = getpass.getpass()
        good_login = impl.verify_password(p)

    impl.derive_enc_key(p)
    main_menu()


def main_menu():
    print('Main Menu')
    print('(1) Retrieve login info')
    print('(2) Register an account')
    print('(3) View accounts')
    print('(4) Modify an account')
    print('(5) Delete an account')
    print('(6) Change master password')
    print('(7) Exit')
    choice = input()
    options = {
    '1' : retrieve_info_menu,
    '2' : register_menu,
    '3' : view_accts_menu,
    '4' : modify_acct_menu,
    '5' : delete_acct_menu,
    '6' : change_master_pw_menu,
    #DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETE
    '0' : show_pw
    #DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETE
    } # should we make an option 7 that exits the application? With safe deletes and everything?
    options.get(choice, exit)()


#DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETE
def show_pw():
    impl.debug_all_passwords()
    main_menu()
#DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETE


def retrieve_info_menu():
    impl.proceed_if_valid_login()
    print('Retrieve an Account')
    results = lookup_choice_menu()

    print('Results: ')
    for i in range(0, len(results)):
        print(i, ': ', impl.acct_directory[results[i]])
        #e.g. 0: {Name: Netflix, ...}

    if len(results) > 0:
        right_choice = False
        while not right_choice:
            account_to_retrieve = input('Type the number of the account whose password you wish to copy: ')
            #e.g. 0
            #Currently doesn't deal with cases where the user doesn't type a number
            confirm_retrieval = input('Are you sure that you want to retrieve the password of account number ' + account_to_retrieve + '? (y or n) ')
            if confirm_retrieval =='y':
                if int(account_to_retrieve) < len(results):
                    right_choice = True
                    index_to_retrieve = results[int(account_to_retrieve)]
                    #e.g. 3
                    impl.copy_pw(index_to_retrieve)
                else:
                    print('That index is not valid. Please enter a valid index')
            elif confirm_retrieval == 'n':
                right_choice = True
                print('Canceling retrieval...')
                #Return to the results
    else:
        print('No accounts matched your search')
    main_menu()


def register_menu():
    impl.proceed_if_valid_login()
    print('Register a new account')
    service_name = input('Service Name: ')
    service_url = input('URL: ')
    username = input('Username: ')
    use_own_pw = input('Use own password (y) or random password (anything else)? ')
    if use_own_pw == 'y':
        password = getpass.getpass()
    else:
        password = impl.get_random_pw()
    impl.register_acct(service_name, service_url, username, password)
    main_menu()


def view_accts_menu():
    impl.proceed_if_valid_login()
    print('All Acounts:')
    impl.print_accts()
    main_menu()


def modify_acct_menu():
    impl.proceed_if_valid_login()
    print('Modify an Account')
    results = lookup_choice_menu()

    print('Results: ')
    for i in range(0, len(results)):
        print(i, ': ', impl.acct_directory[results[i]])

    if len(results) > 0:
        right_choice = False
        while not right_choice:
            account_to_modify = input('Type the number of the account you wish to modify: ')
            #Currently doesn't deal with cases where the user doesn't type a number
            confirm_modify = input('Are you sure that you want to modify account number ' + account_to_modify + '? (y or n) ')
            if confirm_modify =='y':
                if int(account_to_modify) < len(results):
                    right_choice = True
                    index_to_modify = results[int(account_to_modify)]
                    impl.modify_acct(index_to_modify)
                    print('Account Modified')
                else:
                    print('That index is not valid. Please enter a valid index')
            elif confirm_delete == 'n':
                right_choice = True
                print('Canceling modification...')
    else:
        print('No accounts matched your search')
    main_menu()

def delete_acct_menu():
    impl.proceed_if_valid_login()
    print('Delete an Account')
    results = lookup_choice_menu()

    print('Results: ')
    for i in range(0, len(results)):
        print(i, ': ', impl.acct_directory[results[i]])

    if len(results) > 0:
        right_choice = False
        while not right_choice:
            account_to_delete = input('Type the number of the account you wish to delete: ')
            #Currently doesn't deal with cases where the user doesn't type a number
            confirm_delete = input('Are you sure that you want to delete account number ' + account_to_delete + '? (y or n) ')
            if confirm_delete =='y':
                if int(account_to_delete) < len(results):
                    right_choice = True
                    index_to_delete = results[int(account_to_delete)]
                    impl.delete_acct(index_to_delete)
                    print('Account deleted')
                else:
                    print('That index is not valid. Please enter a valid index')
            elif confirm_delete == 'n':
                right_choice = True
                print('Canceling delete...')
    else:
        print('No accounts matched your search')
    main_menu()


def change_master_pw_menu():
    impl.proceed_if_valid_login()
    good_current_pw = False
    while not good_current_pw:
        current_p = getpass.getpass(prompt='Current Password:')
        good_current_pw = impl.verify_password(current_p)
    print('Choose a new password. At least 10 chars, 1 UC, 1 LC, 1 num, 1 special')
    is_good_pw = False
    while not is_good_pw:
        p = getpass.getpass()
        if p == getpass.getpass(prompt='Verify Password:') and impl.check_good_pw(p):
            is_good_pw = True
        else:
            print('Make sure your passwords match, and satisfy the requirements')
    impl.change_master_pw(p)
    main_menu()


def setup_menu():
    impl.proceed_if_valid_login()
    print('Choose a password. At least 10 chars, 1 UC, 1 LC, 1 num, 1 special')
    is_good_pw = False
    while not is_good_pw:
        p = getpass.getpass()
        if p == getpass.getpass(prompt='Verify Password:') and impl.check_good_pw(p):
            is_good_pw = True
        else:
            print('Make sure your passwords match, and satisfy the requirements')
    impl.setup(p)
    impl.set_login_time()
    main_menu()


#returns a list of account indices from a search based on the chosen parameter
def lookup_choice_menu():
    impl.proceed_if_valid_login()
    results = []
    is_valid_choice = False
    while not is_valid_choice:
        lookup_choice = input('Look up account by service name (name), service URL (url), or username (user)?')
        if lookup_choice == 'name':
            is_valid_choice = True
            account_name = input('Service Name: ')
            results = impl.search_by_service_name(account_name)
        elif lookup_choice == 'url':
            is_valid_choice = True
            account_url = input('Service URL: ')
            results = impl.search_by_url(account_url)
        elif lookup_choice == 'user':
            is_valid_choice = True
            account_username = input('Username: ')
            results = impl.search_by_username(account_username)
    return results

#DELETE?
def notify_login_expired():
    print('Your login window has expired. Please restart the program to continue')
    pass
#DELETE?
