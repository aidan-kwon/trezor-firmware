# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p


class KlaytnVerifyMessage(p.MessageType):
    MESSAGE_WIRE_TYPE = 863

    def __init__(
        self,
        signature: bytes = None,
        message: bytes = None,
        address: str = None,
    ) -> None:
        self.signature = signature
        self.message = message
        self.address = address

    @classmethod
    def get_fields(cls):
        return {
            2: ('signature', p.BytesType, 0),
            3: ('message', p.BytesType, 0),
            4: ('address', p.UnicodeType, 0),
        }
