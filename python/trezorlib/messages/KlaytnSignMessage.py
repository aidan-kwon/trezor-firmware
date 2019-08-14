# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class KlaytnSignMessage(p.MessageType):
    MESSAGE_WIRE_TYPE = 862

    def __init__(
        self,
        address_n: List[int] = None,
        message: bytes = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.message = message

    @classmethod
    def get_fields(cls):
        return {
            1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            2: ('message', p.BytesType, 0),
        }
