# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class KlaytnSignTx(p.MessageType):
    MESSAGE_WIRE_TYPE = 858

    def __init__(
        self,
        address_n: List[int] = None,
        nonce: bytes = None,
        gas_price: bytes = None,
        gas_limit: bytes = None,
        to: str = None,
        value: bytes = None,
        data_initial_chunk: bytes = None,
        data_length: int = None,
        chain_id: int = None,
        tx_type: int = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.to = to
        self.value = value
        self.data_initial_chunk = data_initial_chunk
        self.data_length = data_length
        self.chain_id = chain_id
        self.tx_type = tx_type

    @classmethod
    def get_fields(cls):
        return {
            1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            2: ('nonce', p.BytesType, 0),
            3: ('gas_price', p.BytesType, 0),
            4: ('gas_limit', p.BytesType, 0),
            11: ('to', p.UnicodeType, 0),
            6: ('value', p.BytesType, 0),
            7: ('data_initial_chunk', p.BytesType, 0),
            8: ('data_length', p.UVarintType, 0),
            9: ('chain_id', p.UVarintType, 0),
            10: ('tx_type', p.UVarintType, 0),
        }
