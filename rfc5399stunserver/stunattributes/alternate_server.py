from rfc5399stunserver.constants import AttrType
from rfc5399stunserver.stunattributes.mapped_address import MappedAddress


class AlternateServer(MappedAddress):
    def __init__(self, port, ipaddr):
        super().__init__(port, ipaddr)
        self.type = AttrType.ALTERNATE_SERVER
