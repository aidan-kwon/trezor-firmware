from ubinascii import hexlify

from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import chunks, format_amount

from apps.common.confirm import require_confirm, require_hold_to_confirm
from apps.common.layout import split_address
from apps.klaytn import networks, tokens
from apps.klaytn.address import address_from_bytes

TX_TYPE_BASIC = 0
TX_TYPE_FEE_DELEGATION = 1
TX_TYPE_PARTIAL_FEE_DELEGATION = 2

async def require_confirm_tx(ctx, to_bytes, value, chain_id, token=None, tx_type=None):
    if to_bytes:
        to_str = address_from_bytes(to_bytes, networks.by_chain_id(chain_id))
    else:
        to_str = "new contract?"
    text = Text(tx_type_to_string(tx_type), ui.ICON_SEND, ui.GREEN, new_lines=False)
    text.bold(format_klaytn_amount(value, token, chain_id, tx_type))
    text.normal(ui.GREY, "to", ui.FG)
    for to_line in split_address(to_str):
        text.br()
        text.mono(to_line)
    # we use SignTx, not ConfirmOutput, for compatibility with T1
    # await require_confirm(ctx, text, ButtonRequestType.SignTx)


async def require_confirm_fee(
    ctx, spending, gas_price, gas_limit, chain_id, fee_ratio, token=None, tx_type=None
):
    text = Text("Confirm transaction", ui.ICON_SEND, ui.GREEN, new_lines=False)
    text.bold(format_klaytn_amount(spending, token, chain_id, tx_type))
    text.normal(ui.GREY, "Gas price:", ui.FG)
    text.bold(format_klaytn_amount(gas_price, None, chain_id, tx_type))
    text.normal(ui.GREY, "Maximum fee:", ui.FG)
    text.bold(format_klaytn_amount(gas_price * gas_limit, None, chain_id, tx_type))
    if tx_type is not None:
        if to_fee_type(tx_type) == TX_TYPE_FEE_DELEGATION:
            text.normal(ui.ORANGE, "Fee payer will pay the fee", ui.FG)
        elif to_fee_type(tx_type) == TX_TYPE_PARTIAL_FEE_DELEGATION:
            text.normal(ui.ORANGE, "Fee payer pays " + str(fee_ratio) + "%", ui.FG)
    # await require_hold_to_confirm(ctx, text, ButtonRequestType.SignTx)

#TODO require_confirm_fee_delegation

def split_data(data):
    return chunks(data, 18)


async def require_confirm_data(ctx, data, data_total):
    data_str = hexlify(data[:36]).decode()
    if data_total > 36:
        data_str = data_str[:-2] + ".."
    text = Text("Confirm data", ui.ICON_SEND, ui.GREEN)
    text.bold("Size: %d bytes" % data_total)
    text.mono(*split_data(data_str))
    # we use SignTx, not ConfirmOutput, for compatibility with T1
    await require_confirm(ctx, text, ButtonRequestType.SignTx)


def format_klaytn_amount(value: int, token, chain_id: int, tx_type=None):
    if token:
        if token is tokens.UNKNOWN_TOKEN:
            return "Unknown token value"
        suffix = token[2]
        decimals = token[3]
    else:
        suffix = "PEB"
        decimals = 0

    # Don't want to display wei values for tokens with small decimal numbers
    if value > 10 ** (9 + decimals):
        suffix = "STON"
        decimals = 9

    if value > 10 ** (9 + decimals):
        suffix = "KLAY"
        decimals = 18

    return "%s %s" % (format_amount(value, decimals), suffix)


def tx_type_to_string(type):
    if type is None:
        return "LegacyTransaction"

    basic_type = to_basic_type(type)
    if basic_type == 0x08:
        return "ValueTransfer"
    elif basic_type == 0x10:
        return "ValueTransferMemo"
    elif basic_type == 0x28:
        return "ContractDeploy"
    elif basic_type == 0x30:
        return "ContractExecution"
    elif basic_type == 0x38:
        return "Cancel"

    return "Unknown"


def to_basic_type(tx_type):
    return tx_type[0] & ~((1 << 3) -1)

def to_fee_type(tx_type):
    return tx_type[0]%8

