from Zorp.Core import config
from Zorp.Core import init

from Zorp.Core import SockAddrInet, SockAddrInet6
from Zorp.Dispatch import Dispatcher
from Zorp.Service import Service

config.options.kzorp_enabled = False


def default():
    pass
