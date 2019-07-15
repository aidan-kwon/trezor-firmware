from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha3_256
from trezor.messages.KlaytnMessageSignature import KlaytnMessageSignature
from trezor.ui.text import Text
from trezor.utils import HashWriter

from apps.common import paths
from apps.common.confirm import require_confirm
from apps.common.signverify import split_message
from apps.klaytn import CURVE, address

KLAYTN_NETWORK_ID = 8217;

def message_digest(message):
    h = HashWriter(sha3_256(keccak=True))
    signed_message_header = "\x19Klaytn Signed Message:\n"
    h.extend(signed_message_header)
    h.extend(str(len(message)))
    h.extend(message)
    return h.get_digest()


async def sign_message(ctx, msg, keychain):
    await paths.validate_path(
        ctx, address.validate_full_path, keychain, msg.address_n, CURVE
    )
    await require_confirm_sign_message(ctx, msg.message)

    node = keychain.derive(msg.address_n)
    signature = secp256k1.sign(
        node.private_key(),
        message_digest(msg.message),
        False,
        KLAYTN_NETWORK_ID,
    )
    sig = KlaytnMessageSignature()


    sig.address = address.address_from_bytes(node.ethereum_pubkeyhash())
    sig.signature = signature[1:] + bytearray([signature[0]])
    return sig


async def require_confirm_sign_message(ctx, message):
    message = split_message(message)
    text = Text("Sign KLY message", new_lines=False)
    text.normal(*message)
    await require_confirm(ctx, text)
