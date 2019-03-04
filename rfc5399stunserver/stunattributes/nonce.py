import logging

from rfc5399stunserver.constants import AttrType
from rfc5399stunserver.saslprep import SASLprep
from rfc5399stunserver.stun_attribute import STUNAttribute

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Nonce:
    def __init__(self, value):
        if len(SASLprep.saslprep(value)) >= 128:
            logger.error('Too long nonce')
            raise Exception('Too long nonce')
        self.type = AttrType.NONCE
        self.value = SASLprep.saslprep(value).encode('utf-8')

    @property
    def len(self):
        return len(self.value)
