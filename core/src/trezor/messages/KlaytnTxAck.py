# Automatically generated by pb2py
# fmt: off
import protobuf as p


class KlaytnTxAck(p.MessageType):
    MESSAGE_WIRE_TYPE = 861

    def __init__(
        self,
        data_chunk: bytes = None,
    ) -> None:
        self.data_chunk = data_chunk

    @classmethod
    def get_fields(cls):
        return {
            1: ('data_chunk', p.BytesType, 0),
        }
