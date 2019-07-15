from trezor import wire
from trezor.crypto import rlp
from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha3_256
from trezor.messages.KlaytnSignTx import KlaytnSignTx
from trezor.messages.KlaytnTxRequest import KlaytnTxRequest
from trezor.messages.MessageType import KlaytnTxAck
from trezor.utils import HashWriter

from apps.common import paths
from apps.klaytn import CURVE, address, networks, tokens
from apps.klaytn.address import validate_full_path, address_from_bytes
from apps.klaytn.layout import (
    require_confirm_data,
    require_confirm_fee,
    require_confirm_tx,
)

# maximum supported chain id
MAX_CHAIN_ID = 2147483629


async def sign_tx(ctx, msg, keychain):
    msg = sanitize(msg) #TODO refine `sanitize` to support more fields
    check(msg) #TODO refine check to support ~
    await paths.validate_path(ctx, validate_full_path, keychain, msg.address_n, CURVE)

    node = keychain.derive(msg.address_n)
    seckey = node.private_key()
    public_key = secp256k1.publickey(seckey, False)  # uncompressed
    sender_address = sha3_256(public_key[1:], keccak=True).digest()[12:]

    recipient = address.bytes_from_address(msg.to)
    # TODO- check sender and real sender addr

    # await require_confirm_tx(ctx, recipient, value, msg.chain_id, token, msg.tx_type)
    # if token is None and msg.data_length > 0:
    #     await require_confirm_data(ctx, msg.data_initial_chunk, data_total)
    #
    # # TODO if fee delegation tx? -> require_confirm_fee_delegation
    # await require_confirm_fee(
    #     ctx,
    #     value,
    #     int.from_bytes(msg.gas_price, "big"),
    #     int.from_bytes(msg.gas_limit, "big"),
    #     msg.chain_id,
    #     token,
    #     msg.tx_type,
    # )

    data_total = msg.data_length

    data = bytearray()
    data += msg.data_initial_chunk
    data_left = data_total - len(msg.data_initial_chunk)

    total_length = get_total_length(msg, data_total)
    print("total length: ", total_length)

    sha = HashWriter(sha3_256(keccak=True))

    if msg.tx_type is None:
        sha.extend(rlp.encode_length(total_length, True))  # total length

        for field in (msg.nonce, msg.gas_price, msg.gas_limit, recipient, msg.value):
            sha.extend(rlp.encode(field))

        if data_left == 0:
            sha.extend(rlp.encode(data))
        else:
            sha.extend(rlp.encode_length(data_total, False))
            sha.extend(rlp.encode(data, False))

        if msg.chain_id:
            sha.extend(rlp.encode(msg.chain_id))
            sha.extend(rlp.encode(0))
            sha.extend(rlp.encode(0))

    else:
        basic_type = to_basic_type(msg.tx_type)
        attributes = [msg.tx_type, msg.nonce, msg.gas_price, msg.gas_limit]

        # TxTypeValueTransfer(0x08)
        if basic_type == 0x08:
            attributes += [recipient, msg.value, sender_address]
            if is_fee_ratio_type(msg.tx_type):
                attributes.append(msg.fee_ratio)

        # TxTypeValueTransferMemo(0x10), TxTypeSmartContractExecution(0x30)
        elif basic_type == 0x10 or basic_type == 0x30:
            attributes += [recipient, msg.value, sender_address, data]
            if is_fee_ratio_type(msg.tx_type):
                attributes.append(msg.fee_ratio)

        # TxTypeSmartContractDeploy(0x28)
        elif basic_type == 0x28:
            human_readable = 0x00
            if msg.human_readable:
                human_readable = 0x01

            attributes += [recipient, msg.value, sender_address, data, human_readable]
            if is_fee_ratio_type(msg.tx_type):
                attributes.append(msg.fee_ratio)
            attributes.append(msg.code_format)

        # TxTypeCancel(0x38)
        elif basic_type == 0x38:
            attributes.append(sender_address)
            if is_fee_ratio_type(msg.tx_type):
                attributes.append(msg.fee_ratio)

        # not supported tx type
        else:
            raise wire.DataError("Not supported transaction type")

        encoded_out = rlp.encode(attributes)
        sha.extend(rlp.encode([encoded_out, msg.chain_id, 0, 0], True))

    digest = sha.get_digest()
    result = sign_digest(msg, keychain, digest)

    return result


def get_total_length(msg: KlaytnSignTx, data_total: int) -> int:
    length = 0
    if msg.tx_type is not None:
        length += rlp.field_length(1, msg.tx_type)

    length += rlp.field_length(len(msg.nonce), msg.nonce[:1])
    length += rlp.field_length(len(msg.gas_price), msg.gas_price)
    length += rlp.field_length(len(msg.gas_limit), msg.gas_limit)
    to = address.bytes_from_address(msg.to)
    length += rlp.field_length(len(to), to)
    length += rlp.field_length(len(msg.value), msg.value)

    if msg.chain_id:  # forks replay protection
        if msg.chain_id < 0x100:
            l = 1
        elif msg.chain_id < 0x10000:
            l = 2
        elif msg.chain_id < 0x1000000:
            l = 3
        else:
            l = 4
        length += rlp.field_length(l, [msg.chain_id])
        length += rlp.field_length(0, 0)
        length += rlp.field_length(0, 0)

    length += rlp.field_length(data_total, msg.data_initial_chunk)
    return length


async def send_request_chunk(ctx, data_left: int):
    # TODO: layoutProgress ?
    req = KlaytnTxRequest()
    if data_left <= 1024:
        req.data_length = data_left
    else:
        req.data_length = 1024

    return await ctx.call(req, KlaytnTxAck)


def sign_digest(msg: KlaytnSignTx, keychain, digest):
    node = keychain.derive(msg.address_n)
    signature = secp256k1.sign(
        node.private_key(), digest, False, secp256k1.CANONICAL_SIG_ETHEREUM #TODO check secp256k1 library
    )

    req = KlaytnTxRequest()
    req.signature_v = signature[0]
    if msg.chain_id > MAX_CHAIN_ID:
        req.signature_v -= 27
    elif msg.chain_id:
        req.signature_v += 2 * msg.chain_id + 8

    req.signature_r = signature[1:33]
    req.signature_s = signature[33:]

    return req


def check(msg: KlaytnSignTx):
    # if msg.tx_type not in [1, 6, None]:
    #     raise wire.DataError("tx_type out of bounds")

    if msg.chain_id < 0:
        raise wire.DataError("chain_id out of bounds")

    if msg.data_length > 0:
        if not msg.data_initial_chunk:
            raise wire.DataError("Data length provided, but no initial chunk")
        # Our encoding only supports transactions up to 2^24 bytes. To
        # prevent exceeding the limit we use a stricter limit on data length.
        if msg.data_length > 16000000:
            raise wire.DataError("Data length exceeds limit")
        if len(msg.data_initial_chunk) > msg.data_length:
            raise wire.DataError("Invalid size of initial chunk")

    # safety checks
    if not check_gas(msg) or not check_to(msg):
        raise wire.DataError("Safety check failed")

def check_type(msg: KlaytnSignTx) -> bool:
    if msg.tx_type is None:
        return check(msg)
    elif msg.tx_type == b'\x08':
        # if len(msg) != 8:
        #     return False
        if msg.nonce is None or msg.value is None:
            return False
        return True


def check_gas(msg: KlaytnSignTx) -> bool:
    if msg.gas_price is None or msg.gas_limit is None:
        return False
    if len(msg.gas_price) + len(msg.gas_limit) > 30:
        # sanity check that fee doesn't overflow
        return False
    return True


def check_to(msg: KlaytnTxRequest) -> bool:
    if msg.to == "":
        if msg.data_length == 0:
            # sending transaction to address 0 (contract creation) without a data field
            # return False #TODO-Aidan
            return True
    else:
        if len(msg.to) not in (40, 42):
            return False
    return True


def sanitize(msg):
    if msg.value is None:
        msg.value = b""
    if msg.data_initial_chunk is None:
        msg.data_initial_chunk = b""
    if msg.data_length is None:
        msg.data_length = 0
    if msg.to is None:
        msg.to = ""
    if msg.nonce is None:
        msg.nonce = b""
    if msg.chain_id is None:
        msg.chain_id = 0
    return msg


def to_basic_type(tx_type):
    return tx_type[0] & ~((1 << 3) -1)

def is_fee_ratio_type(tx_type):
    return tx_type[0]%8 == 2
