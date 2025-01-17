from trezor.messages.KlaytnPublicKey import KlaytnPublicKey
from trezor.messages.HDNodeType import HDNodeType

from apps.common import coins, layout, paths
from apps.klaytn import CURVE, address


async def get_public_key(ctx, msg, keychain):
    await paths.validate_path(
        ctx, address.validate_path_for_get_public_key, keychain, msg.address_n, CURVE
    )
    node = keychain.derive(msg.address_n)

    # we use the Bitcoin format for Klaytn xpubs
    btc = coins.by_name("Bitcoin")
    node_xpub = node.serialize_public(btc.xpub_magic)

    pubkey = node.public_key()
    if pubkey[0] == 1:
        pubkey = b"\x00" + pubkey[1:]
    node_type = HDNodeType(
        depth=node.depth(),
        child_num=node.child_num(),
        fingerprint=node.fingerprint(),
        chain_code=node.chain_code(),
        public_key=pubkey,
    )

    if msg.show_display:
        await layout.show_pubkey(ctx, pubkey)

    return KlaytnPublicKey(node=node_type, xpub=node_xpub)
