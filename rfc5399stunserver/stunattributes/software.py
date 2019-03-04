import logging

from rfc5399stunserver.constants import AttrType
from rfc5399stunserver.saslprep import SASLprep
from rfc5399stunserver.stun_attribute import STUNAttribute

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Software(STUNAttribute):
    def __init__(self, value):
        if len(SASLprep.saslprep(value)) >= 128:
            logger.error('Too long software text')
            raise Exception('Too long software text')
        self.type = AttrType.SOFTWARE
        self.value = SASLprep.saslprep(value).encode('utf-8')

    @property
    def length(self):
        return len(self.value)
