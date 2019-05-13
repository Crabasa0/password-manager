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
        p = getpass.getpass() # if we ever use stdout for useful output, we should use getpass.getpass(stream=sys.stderr) so that the password doesn't get output as part of stdout
        good_login = impl.verify_password(p)

    impl.derive_enc_key(p)
    main_menu()

    #pass

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
    '6' : change_master_pw_menu
    } # should we make an option 7 that exits the application? With safe deletes and everything?
    options.get(choice, exit)() #should that second pair of parentheses be inside the first? So options.get(choice, exit())
    #repeat after me: First. Class. Values.


def retrieve_info_menu():
    print('Retrieve an Account')
    is_valid_choice = False
    while not is_valid_choice:
        lookup_choice = input('Look up account by service name (name), service URL (url), or username (user)')
        if lookup_choice == 'name':
            is_valid_choice = True
            account_name = input('Service Name: ')
            impl.search_by_service_name(account_name)
        elif lookup_choice == 'url':
            is_valid_choice = True
            account_url = input('Service URL: ')
            impl.search_by_url(account_url)
        elif lookup_choice == 'user':
            is_valid_choice = True
            account_username = input('Username: ')
            impl.search_by_username(account_username)


def register_menu():
    print('Register a new account')
    service_name = input('Service Name: ')
    service_url = input('URL: ')
    username = input('Username: ')
    use_own_pw = input('Use own password (y) or random password (anything else)?')
    if use_own_pw == 'y':
        password = getpass.getpass()
    else:
        password = impl.get_random_pw()
    impl.register_acct(service_name, service_url, username, password)
    main_menu()

def view_accts_menu():
    print('All Acounts:')
    impl.print_accts()

def modify_acct_menu():
    print('Modify an Account')
    is_valid_choice = False
    while not is_valid_choice:
        lookup_choice = input('Look up account by service name (name), service URL (url), or username (user)?')
        if lookup_choice == 'name':
            is_valid_choice = True
            account_name = input('Service Name: ')
            impl.search_by_service_name(account_name)
        elif lookup_choice == 'url':
            is_valid_choice = True
            account_url = input('Service URL: ')
            impl.search_by_url(account_url)
        elif lookup_choice == 'user':
            is_valid_choice = True
            account_username = input('Username: ')
            impl.search_by_username(account_username)
    pass

def delete_acct_menu():
    print('Delete an Account')
    is_valid_choice = False
    while not is_valid_choice:
        lookup_choice = input('Look up account by service name (name), service URL (url), or username (user)?')
        if lookup_choice == 'name':
            is_valid_choice = True
            account_name = input('Service Name: ')
            impl.search_by_service_name(account_name)
        elif lookup_choice == 'url':
            is_valid_choice = True
            account_url = input('Service URL: ')
            impl.search_by_url(account_url)
        elif lookup_choice == 'user':
            is_valid_choice = True
            account_username = input('Username: ')
            impl.search_by_username(account_username)
    pass

def change_master_pw_menu():
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
    pass

def setup_menu():
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


def notify_login_expired():
    pass
