import logging

from rfc5399stunserver.constants import MsgClass, MethodType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class STUNHeader:
    def __init__(self):
        self.message_class = MsgClass.FAILURE_RESPONSE
        self.message_method = MethodType.BINDING
        self.message_length = 0
        self.magic_cookie = bytes.fromhex('2112A442')
        # self.magic_cookie = socket.htonl(0x2112A442).to_bytes(4, 'big')
        self.transaction_id = bytes(96)

    def create_msg_type(self):
        method_high = self.message_method & ~((1 << 7) - 1)
        method_mid = self.message_method & ((1 << 7) - 1) & ~((1 << 4) - 1)
        method_low = self.message_method & ((1 << 4) - 1)
        class_high = self.message_class & 2
        class_low = self.message_class & 1
        return ((method_high << 2) + (method_mid << 1) + method_low +
                (class_high << 7) + (class_low << 4)).to_bytes(2, 'big')

    @property
    def bin(self):
        return (self.create_msg_type() +
                self.message_length.to_bytes(2, 'big') +
                self.magic_cookie + self.transaction_id)
