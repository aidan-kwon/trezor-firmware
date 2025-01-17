# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .HDNodeType import HDNodeType


class KlaytnPublicKey(p.MessageType):
    MESSAGE_WIRE_TYPE = 851

    def __init__(
        self,
        node: HDNodeType = None,
        xpub: str = None,
    ) -> None:
        self.node = node
        self.xpub = xpub

    @classmethod
    def get_fields(cls):
        return {
            1: ('node', HDNodeType, 0),
            2: ('xpub', p.UnicodeType, 0),
        }
