import inspect

import loguru
from slither import Slither
from slither.detectors import all_detectors
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.printers.functions.cfg import CFG

from .solc_utils import SOLC_BIN_PATH


class BugInfo:
    def __init__(self, start_pos, length, content, bug_type, line_num, slither_node_type, slither_addtional_field, origin_bug=False, func_sig=""):
        """
        origin_bug的意义只有在启用了SmartBugs的人工标注作为目标时, 才具有真正的意义, 其他情况下均为False, 无意义
        在SmartBugs的人工标注作为目标时 ,若origin_bug为True, 则代表着这个BugIngo是人工标注的漏洞行数, 应用于分别作为目标的场景下

        func_sig只有在SmartBugs的人工标注作为目标时, 才具有意义
        这个成员变量意味着指定漏洞的所存在的函数签名, 应同时作为目标, 否则无法检测
        在Slither模式作为目标时, 函数签名就已经被SLither识别, 无需我们再分析func_sig

        """
        self.start_pos = start_pos
        self.length = length
        self.content = content
        self.bug_type = bug_type
        self.line_num = line_num
        self.slither_node_type = slither_node_type
        self.slither_addtional_field = slither_addtional_field
        self.is_finded_in_src_map = False
        self.origin_bug = origin_bug
        self.func_sig = func_sig

    def __str__(self):
        return f"content:{self.content}, start_pos:{self.start_pos}, 漏洞类型:{self.bug_type}"


def get_slither_only(_sol_path):
    try:
        sl = Slither(_sol_path, solc=SOLC_BIN_PATH)
        return sl
    except BaseException as e:
        loguru.logger.error("获得slither时出现错误,{e}")
        return None


def get_slither_results(_sol_path):
    try:
        sl = Slither(_sol_path, solc=SOLC_BIN_PATH)
        detectors = [getattr(all_detectors, name)
                     for name in dir(all_detectors)]
        detectors = [d for d in detectors if inspect.isclass(
            d) and issubclass(d, AbstractDetector)]
        temp_d = []
        for d in detectors:
            if d.IMPACT == DetectorClassification.HIGH or d.IMPACT == DetectorClassification.MEDIUM or d.IMPACT == DetectorClassification.LOW:
                temp_d.append((d, d.ARGUMENT))
        detectors = temp_d
        for detector, simple_name in detectors:
            sl.register_detector(detector)
        results = sl.run_detectors()
        bug_infos = dict()
        for i, result in enumerate(results):
            if len(result) != 0:
                for j, one_bug in enumerate(result):
                    for k, element in enumerate(one_bug['elements']):
                        detector, simple_name = detectors[i]
                        node_type = element['type']
                        # 检测到函数，函数仍是可以作为字节码映射的一部分，但是需要特殊标记node_type,在对slither检测的漏洞的结果分析的时候，需要过滤掉这个
                        # if node_type == 'function':
                        #     loguru.logger.info(f"slither检测到{simple_name}漏洞，type为'function'，跳过'{element['name']}'")
                        #     continue

                        # 回调函数无法在策略1中检测
                        # if element['type'] == 'function' and element['name'] == 'fallback':
                        #     loguru.logger.error(f"slither检测到{simple_name}漏洞，type为'回调',跳过")
                        #     continue
                        # 如果检测变量，那么有些变量在初始状态的成员函数里，会导致策略1失败
                        # if element['type'] == 'variable':
                        #     loguru.logger.error(f"slither检测到{simple_name}漏洞，type为'variable'，跳过'{element['name']}'")
                        #     continue
                        if "lines" not in element['source_mapping'].keys():
                            line = 0
                        else:
                            line = element['source_mapping']['lines'][0]
                        # 这个manticore不会报告，无法进行匹配
                        # if 'additional_fields' in element.keys() and 'underlying_type' in element[
                        #     'additional_fields'] and \
                        #         element['additional_fields']['underlying_type'] == 'variables_written':
                        #     loguru.logger.error(
                        #         f"slither检测到{simple_name}漏洞，为'additional_fields['underlying_type']=='variables_written''，"
                        #         f"跳过{line}-'{element['name']}'")
                        #     continue
                        additional_fields = element.get(
                            "additional_fields", {})
                        bug_info = BugInfo(element['source_mapping']['start'],
                                           element['source_mapping']['length'],
                                           element['name'], simple_name, line, node_type, additional_fields)
                        loguru.logger.warning(
                            f"Slither发现漏洞:{line}行-{bug_info}")
                        if line not in bug_infos.keys():
                            bug_infos[line] = [bug_info]
                        else:
                            bug_infos[line].append(bug_info)
        contract_line_map = dict()
        for contract_unit in sl.contracts:
            contract_line_map[contract_unit.name] = contract_unit.source_mapping_str
        return bug_infos, contract_line_map, sl
    except Exception as e:
        loguru.logger.error(f"Slither检测出错，错误信息为{e}")
        return None, None, None
