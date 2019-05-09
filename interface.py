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
    pass

def retrieve_info_menu():
    pass

def register_menu():
    pass

def view_accts_menu():
    pass

def modify_acct_menu():
    pass

def delete_acct_menu():
    pass

def change_master_pw_menu():
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