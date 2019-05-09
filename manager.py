#
#
#   This is what the user runs
#
import interface
import impl

from os.path import isfile

#prevent page swapping, courtesy of kopchik on GitHub
import ctypes
MCL_CURRENT = 1
MCL_FUTURE  = 2
libc = ctypes.CDLL('libc.so.6', use_errno=True)
def mlockall(flags=MCL_CURRENT|MCL_FUTURE):
    result = libc.mlockall(flags)
    if result != 0:
        raise Exception("cannot lock memmory, errno=%s" % ctypes.get_errno())


def run():
    mlockall()
    if isfile(impl.VERIFICATION_HASH_URL):
        interface.login_menu()
    else:
        interface.setup_menu()
    pass

def run_debug():
    interface.login_menu()

run()
