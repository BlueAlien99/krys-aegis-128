import aes._utils as utils


def aes_round(state, key):
    x = utils.transpose(utils.bytes2matrix(state))

    x = utils.sub_bytes(x)
    x = utils.shift_rows(x)
    x = utils.mix_columns(x)
    x = utils.add_round_key(utils.bytes2matrix(key), x)

    return utils.matrix2bytes(utils.transpose(x))
