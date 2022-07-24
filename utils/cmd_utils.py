import os

import loguru


def run_cmd(_cmd, _print=True):
    if _print:
        loguru.logger.info(f"准备执行的命令是:{_cmd}")
    output = os.popen(cmd=_cmd).readlines()
    return output
