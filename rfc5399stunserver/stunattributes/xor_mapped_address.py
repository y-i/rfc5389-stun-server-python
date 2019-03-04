import ipaddress
import logging

from rfc5399stunserver.constants import AttrType
from rfc5399stunserver.stunattributes.mapped_address import MappedAddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class XorMappedAddress(MappedAddress):
    def __init__(self, port, ipaddr):
        self.type = AttrType.XOR_MAPPED_ADDRESS
        self.port = port ^ 0x2112
        self.ipaddr = ipaddress.ip_address(
            ipaddr ^ 0x2112A442)  # v6の場合transactionIDも入る
        self.isIPv6 = self.ipaddr.version == 6
