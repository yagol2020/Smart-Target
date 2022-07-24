import evm_cfg_builder.cfg as cfg_builder
import loguru

def create_cfg(_runtime_bytecode) -> cfg_builder.CFG:
    try:
        cfg = cfg_builder.CFG(_runtime_bytecode)
    except BaseException as e:
        loguru.logger.error(e)
        cfg = None
    return cfg
