# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from . import messages as proto
from .tools import CallException, expect, normalize_nfc, session


def int_to_big_endian(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


# ====== Client functions ====== #


@expect(proto.KlaytnAddress, field="address")
def get_address(client, n, show_display=False, multisig=None):
    return client.call(proto.KlaytnGetAddress(address_n=n, show_display=show_display))


@expect(proto.KlaytnPublicKey)
def get_public_node(client, n, show_display=False):
    return client.call(
        proto.KlaytnGetPublicKey(address_n=n, show_display=show_display)
    )


@session
def sign_tx(
        client,
        n,
        nonce,
        gas_price,
        gas_limit,
        value=None,
        to=None,
        chain_id=None,
        tx_type=None,
        human_readable=None,
        code_format=None,
        data=None,
        fee_ratio=None,
):

    msg = proto.KlaytnSignTx(
        address_n=n,
        nonce=int_to_big_endian(nonce),
        gas_price=int_to_big_endian(gas_price),
        gas_limit=int_to_big_endian(gas_limit),
    )

    if to is not None:
        msg.to = to

    if tx_type is not None:
        msg.tx_type = tx_type

    if human_readable is not None:
        msg.human_readable = human_readable

    if code_format is not None:
        msg.code_format = code_format

    if data is not None:
        msg.data_length = len(data)
        # data, chunk = data[1024:], data[:1024]
        # msg.data_initial_chunk = chunk
        msg.data_initial_chunk = data

    if value is not None:
        msg.value = int_to_big_endian(value)

    if chain_id is not None:
        msg.chain_id = chain_id

    if fee_ratio is not None:
        msg.fee_ratio = fee_ratio

    response = client.call(msg)

    # while response.data_length is not None:
    #     data_length = response.data_length
    #     data, chunk = data[data_length:], data[:data_length]
    #     response = client.call(proto.KlaytnTxAck(data_chunk=chunk))

    # https://github.com/trezor/trezor-core/pull/311
    # only signature bit returned. recalculate signature_v
    if response.signature_v <= 1:
        response.signature_v += 2 * chain_id + 35

    return response.signature_v, response.signature_r, response.signature_s

@expect(proto.KlaytnMessageSignature)
def sign_message(client, n, message):
    message = normalize_nfc(message)
    return client.call(proto.KlaytnSignMessage(address_n=n, message=message))


def verify_message(client, address, signature, message):
    message = normalize_nfc(message)
    try:
        resp = client.call(
            proto.KlaytnVerifyMessage(
                address=address, signature=signature, message=message
            )
        )
    except CallException as e:
        resp = e
    if isinstance(resp, proto.Success):
        return True
    return False
