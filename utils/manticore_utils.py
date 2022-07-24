import json

import loguru
import timeout_decorator

from manticore_target.manticore.ethereum.cli import get_detectors_classes
from utils import my_utils
from manticore_target.manticore.ethereum import manticore, DetectReentrancyAdvanced, DetectReentrancySimple, \
    DetectExternalCallAndLeak, \
    DetectEnvInstruction, DetectManipulableBalance, DetectUninitializedStorage, DetectUninitializedMemory, \
    DetectUnusedRetVal, DetectSuicidal, DetectDelegatecall
from manticore_target.manticore.ethereum.plugins import KeepOnlyIfStorageChanges

from utils.solc_utils import SOLC_BIN_PATH


def fully_get_manticore_result(_output_dir, _sol_path, _contract_name):
    with open("target_file/target.json", "w") as target_json:
        json.dump({"target": False}, target_json)

    with open("target_file/stop_condition.json", "r") as f:
        stop_condition = json.load(f)
        stop_condition['mode'] = 'fully'
    with open("target_file/stop_condition.json", "w") as f:
        json.dump(stop_condition, f)

    return manticore_core_runner(_output_dir, _sol_path, _contract_name, _mode="fully")


def target_get_manticore_result(_output_dir, _sol_path, _contract_name):
    with open("target_file/stop_condition.json", "r") as f:
        stop_condition = json.load(f)
        stop_condition['mode'] = 'target'
    with open("target_file/stop_condition.json", "w") as f:
        json.dump(stop_condition, f)

    return manticore_core_runner(_output_dir, _sol_path, _contract_name, _mode="target")


def manticore_core_runner(_output_dir, _sol_path, _contract_name, _mode):
    try:
        m = manticore.ManticoreEVM(workspace_url=_output_dir)
        all_detector_classes = get_detectors_classes()
        detectors = {d.ARGUMENT: d for d in all_detector_classes}
        m.register_plugin(KeepOnlyIfStorageChanges())
        for k, v in detectors.items():
            m.register_detector(v())
        # m.register_detector(DetectReentrancyAdvanced())  # reentrancy
        # m.register_detector(DetectReentrancySimple())  # reentrancy
        # m.register_detector(DetectExternalCallAndLeak())  # arbitrarySend
        # m.register_detector(DetectEnvInstruction())  # Timestamp
        # m.register_detector(DetectManipulableBalance())  # IncorrectStrictEquality
        # m.register_detector(DetectUninitializedStorage())
        # m.register_detector(DetectUninitializedMemory())
        # m.register_detector(DetectUnusedRetVal())
        # m.register_detector(DetectSuicidal())
        # m.register_detector(DetectDelegatecall())
        ctor_arg = (m.make_symbolic_value(),)
        result = m.multi_tx_analysis(_sol_path, contract_name=_contract_name, compile_args={"solc": SOLC_BIN_PATH},
                                     tx_send_ether=True,tx_limit=2)
        if result == -1:
            loguru.logger.error("manticore运行失败")
            return -1
        m.finalize()
        global_findings = m.global_findings
        loguru.logger.info(f"模式为{_mode},结果为{global_findings}")
        return global_findings
    except timeout_decorator.TimeoutError as t_error:
        loguru.logger.error(f"manticore运行超时,{t_error}")
        return -2
    except Exception as e:
        loguru.logger.error(f"模式为{_mode},manticore出现异常{e}")
        return -3


def analysis_output(_findings_fully, _findings_target, _output_dir, _slither_bug_infos):
    not_bug_type_target, not_bug_line_target, manticore_findings_target = my_utils.check_findings_with_slither(
        _mode='target',
        _output_dir=_output_dir,
        _slither_bug_infos=_slither_bug_infos)
    not_bug_type_fully, not_bug_line_fully, manticore_findings_fully = my_utils.check_findings_with_slither(
        _mode='fully',
        _output_dir=_output_dir,
        _slither_bug_infos=_slither_bug_infos)
    if _findings_fully == _findings_target:
        loguru.logger.info(f"制导与非制导的漏洞检测结果相同")
    else:
        loguru.logger.info("制导与非制导的漏洞检测结果不同")
        target_more_than_fully = _findings_target - _findings_fully
        diff_mode(_more_findings_all_content=manticore_findings_target,
                  _more_findings=target_more_than_fully, _which_more='target')
        fully_more_than_target = _findings_fully - _findings_target
        diff_mode(_more_findings_all_content=manticore_findings_fully, _more_findings=fully_more_than_target,
                  _which_more='fully')


def diff_mode(_more_findings_all_content, _more_findings, _which_more):
    """
    比较两个模式的动态检测结果之间的差异
    
    :param _more_findings_all_content: 检测漏洞多的模式的全部结果，以这个作为基础进行遍历
    :param _more_findings: 多检测漏洞的fings，这个里面包含了pc，以pc作为基础进行检测
    :param _which_more:  当前的检测模式，即是制导多还是非制导的多
    :return: 
    """
    if _more_findings is not set():
        if _which_more == 'target':
            loguru.logger.info(f"制导比非制导多{_more_findings}")
        elif _which_more == 'fully':
            loguru.logger.info(f"非制导比制导多{_more_findings}")
        for address, pc, finding, at_init in _more_findings:
            for line, bugs in _more_findings_all_content.items():
                if line == 'coverage':
                    continue
                for bug_info in bugs:
                    for bug_info_pc in bug_info.pc:
                        if bug_info_pc == pc:
                            if _which_more == 'target':
                                loguru.logger.info(f"制导比非制导多的漏洞行号为{line}")
                            elif _which_more == 'fully':
                                loguru.logger.info(f"非制导比制导多的漏洞行号为{line}")
