import logging

from rfc5399stunserver.constants import AttrType
from rfc5399stunserver.saslprep import SASLprep
from rfc5399stunserver.stun_attribute import STUNAttribute

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Realm:
    def __init__(self, value):
        if len(SASLprep.saslprep(value)) >= 128:
            logger.error('Too long realm')
            raise Exception('Too long realm')
        self.type = AttrType.REALM
        self.value = SASLprep.saslprep(value).encode('utf-8')

    @property
    def length(self):
        return len(self.value)
