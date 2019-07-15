from trezor import wire
from trezor.messages import MessageType

from apps.common import HARDENED
from apps.klaytn.networks import all_slip44_ids_hardened

CURVE = "secp256k1"


def boot():
    ns = [[CURVE, HARDENED | 44, HARDENED | 8217]]
    wire.add(MessageType.KlaytnGetAddress, __name__, "get_address", ns)
    wire.add(MessageType.KlaytnGetPublicKey, __name__, "get_public_key", ns)
    wire.add(MessageType.KlaytnSignTx, __name__, "sign_tx", ns)
    wire.add(MessageType.KlaytnSignMessage, __name__, "sign_message", ns)
    wire.add(MessageType.KlaytnVerifyMessage, __name__, "verify_message")
