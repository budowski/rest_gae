from rest_gae import RESTHandler, PERMISSION_ANYONE, PERMISSION_LOGGED_IN_USER, PERMISSION_OWNER_USER, PERMISSION_ADMIN

__all__ = ['RESTHandler', 'PERMISSION_ANYONE', 'PERMISSION_LOGGED_IN_USER', 'PERMISSION_OWNER_USER', 'PERMISSION_ADMIN']

VERSION = (1, 1, 0)

def get_version():
    if isinstance(VERSION[-1], basestring):
        return '.'.join(map(str, VERSION[:-1])) + VERSION[-1]
    return '.'.join(map(str, VERSION))

__version__ = get_version()

