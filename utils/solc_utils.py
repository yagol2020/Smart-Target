from crytic_compile import CryticCompile

import utils.cmd_utils

SOLC_BIN_PATH = "solc"
SOLC_SELECT_PATH = "solc-select"


def change_solc_version(_solc_version, _print=True):
    """
    更换solc版本
    :param _print:
    :param _solc_version:
    :return:
    """
    utils.cmd_utils.run_cmd(f"{SOLC_SELECT_PATH} use {_solc_version}", _print=_print)


def gen_compile_cmd(_sol_path, _output_dir):
    return f"{SOLC_BIN_PATH} --output-dir {_output_dir} --overwrite --asm --combined-json bin,bin-runtime,opcodes {_sol_path}"


def compile_sol(_sol_path) -> CryticCompile:
    """
    编译sol文件
    :param _sol_path: sol文件的绝对地址
    :return:
    """

    compile_result = CryticCompile(target=_sol_path, **{"solc": SOLC_BIN_PATH})
    return compile_result
