# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class NEMGetAddress(p.MessageType):
    MESSAGE_WIRE_TYPE = 67

    def __init__(
        self,
        address_n: List[int] = None,
        network: int = None,
        show_display: bool = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.network = network
        self.show_display = show_display

    @classmethod
    def get_fields(cls):
        return {
            1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            2: ('network', p.UVarintType, 0),
            3: ('show_display', p.BoolType, 0),
        }
