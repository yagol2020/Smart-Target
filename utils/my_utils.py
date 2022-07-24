import os
from pyclbr import Function
import shutil
import sys
from typing import Dict, List, Tuple
import json
import loguru
import pyevmasm as EVMAsm
from evm_cfg_builder import CFG
from evm_cfg_builder.cfg import CFG
from slither import Slither
from slither.core.declarations.function import FunctionType
from slither.core.expressions import AssignmentOperation
from slither.core.expressions import CallExpression
from slither.core.expressions import TypeConversion
from slither.core.declarations import FunctionContract
from slither.core.expressions.literal import Literal
from slither.core.expressions.identifier import Identifier
from slither.core.solidity_types.mapping_type import MappingType
from utils import cmd_utils
from utils.slither_utils import BugInfo
from utils.solc_utils import gen_compile_cmd


def clean_workdir():
    shutil.rmtree("/home/yagol/Desktop/Smart-Target/target_file")
    os.mkdir("/home/yagol/Desktop/Smart-Target/target_file")
    shutil.rmtree("output_dir")
    os.mkdir("output_dir/")


def gen_sources_map(compile_unit, contract_name):
    try:
        runtime_src_map = compile_unit.srcmap_runtime(contract_name)
        runtime_src_map = build_source_map(bytecode=compile_unit.bytecodes_runtime[contract_name],
                                           src_map=runtime_src_map)
    except Exception as e:
        loguru.logger.error(f"在解析sources_map时发现异常:{e}")
        runtime_src_map = None
    # revert_sources_map(runtime_src_map)  # 生成pc_map_line.json文件，这个文件用于在manticore的detector中判断pc和源代码行号之间的关系, Mythril暂时不读取这个文件，这是用来判断终止条件的
    return runtime_src_map


def revert_sources_map(src_map):
    revert_dict = {}
    if src_map is not None:
        for key, value in src_map.items():
            for v in value:
                if v in revert_dict.keys():
                    loguru.logger.error("单一指令在多个源代码中出现")
                revert_dict[v] = key
    with open("/root/smart_target/target_file/pc_map_line.json", "w") as f:
        json.dump(revert_dict, f)


def build_source_map(bytecode, src_map):
    """
    power by manticore, modify by yagol
    返回如下格式的源代码映射：源代码->指令位置
    {
        "483:24":[0x14C, 0x22B],
        "521:32":[0x23C, 0x34B]
    }
    :param bytecode:
    :param src_map:
    :return:
    """
    bytecode = bytes.fromhex(bytecode)
    bytecode = _without_metadata(bytecode=bytecode)
    new_src_map = {}
    if bytecode and src_map:
        asm_offset = 0
        asm_pos = 0
        md = dict(enumerate(src_map[asm_pos].split(":")))
        byte_offset = int(md.get(0, 0))
        source_len = int(md.get(1, 0))
        pos_to_offset = {}
        for i in EVMAsm.disassemble_all(bytecode):
            pos_to_offset[asm_pos] = asm_offset
            asm_pos += 1
            asm_offset += i.size
        for asm_pos, md in enumerate(src_map):
            if len(md):
                d = {p: k for p, k in enumerate(md.split(":")) if k}
                byte_offset = int(d.get(0, byte_offset))  # 483
                source_len = int(d.get(1, source_len))  # 24
            key = f"{byte_offset}:{source_len}"
            if key not in new_src_map.keys():
                new_src_map[key] = [pos_to_offset[asm_pos]]
            else:
                new_src_map[key].append(pos_to_offset[asm_pos])
    return new_src_map


def _without_metadata(bytecode):
    end = None
    if (
            bytecode[-43:-34] == b"\xa1\x65\x62\x7a\x7a\x72\x30\x58\x20"
            and bytecode[-2:] == b"\x00\x29"
    ):
        end = -9 - 32 - 2
    return bytecode[:end]


def extract_runtime_bin_from_combined_json(_combined_json_path, _contract_name, _sol_path):
    import json
    with open(_combined_json_path, "r") as combined_json_file:
        combined_json = json.load(combined_json_file)
        bin_runtime = combined_json["contracts"][f"{_sol_path}:{_contract_name}"]["bin-runtime"]
    return bin_runtime


def extract_asm_from_asm(_compiled_output_path, _contract_name):
    with open(f"{_compiled_output_path}/{_contract_name}.evm", "r") as asm_file:
        asm_file_contents = asm_file.readlines()
    return asm_file_contents


def located_base_block_from_bug_infos(_cfg: CFG, _sol_path: str, _bug_infos, _src_map, _output_dir,
                                      _contract_name) -> Tuple[CFG, int]:
    chose_method = None
    loguru.logger.info(f"想要寻找的bug_infos: {_bug_infos}")
    if _src_map is not None:
        # 策略1，利用_source_map定位源代码和指令之间的关系
        bug_ins_set = get_bug_blocks_use_sources_map(_source_map=_src_map, _bug_infos=_bug_infos)
    else:
        """
        source_map为None,则使用策略2
        """
        bug_ins_set = None
    if bug_ins_set is None:
        # 策略2，利用asm定位源代码和指令之间的关系
        loguru.logger.info("正在切换到策略2")
        cmd_utils.run_cmd(_cmd=gen_compile_cmd(
            _sol_path=_sol_path, _output_dir=_output_dir))
        _asm_contents = extract_asm_from_asm(
            _compiled_output_path=_output_dir, _contract_name=_contract_name)
        bug_blocks = get_bug_blocks_use_asm(
            _asm_contents=_asm_contents, _bug_infos=_bug_infos)  # 从ASM文件中获得存在漏洞的指令List
        check_cfg_with_bug_blocks(_be_check_bb=_cfg.entry_point,_bug_blocks=bug_blocks, _bug_ins_set=None)  # 从CFG中定位漏洞
        chose_method = 2
    else:
        check_cfg_with_bug_blocks(_be_check_bb=_cfg.entry_point, _bug_blocks=None,_bug_ins_set=bug_ins_set)  # 从CFG中定位漏洞
        chose_method = 1
    # 不管你用什么策略，都需要把_cfg处理好，里面要有bug属性
    cfg_with_target = gen_target_output(
        _cfg=_cfg, output_dir=_output_dir)  # 从CFG中输出制导信息
    return cfg_with_target, chose_method


def get_bug_blocks_use_sources_map(_source_map: dict, _bug_infos):
    bug_ins_set = set()
    for k, v in _bug_infos.items():
        for i, bug_info in enumerate(v):
            location = f"{bug_info.start_pos}:{bug_info.length}"
            if location in _source_map.keys():  # 只要能解析出来src map，那么就用策略1
                bug_info.is_finded_in_src_map = True
                for bug_ins in _source_map[location]:
                    bug_ins_set.add(bug_ins)
            # else:
            #     loguru.logger.error(f"source_map没有这个漏洞{location}源代码的指令信息,切换到策略2")
            #     return None
    return bug_ins_set


def get_bug_blocks_use_asm(_asm_contents, _bug_infos):
    """
    策略2,不算特别合理，作为策略1的备选，若策略1未能找到对应源代码的指令集，则启用策略2
    不合理的地方体现在，我们对基本块的分割

    :param _asm_contents:
    :param _bug_infos:
    :return:
    """
    bug_source_location = list()
    for k, v in _bug_infos.items():
        for i, bug_info in enumerate(v):  # 不使用源代码匹配，而是用行好和offset匹配，这样稍微合理一点
            location = f"{bug_info.start_pos}:{bug_info.start_pos + bug_info.length}"
            bug_source_location.append(location)
    bug_blocks = list()
    temp_list = list()
    append_flag = False
    append_line_number = ""
    for asm_line in _asm_contents:
        if (asm_line.strip().startswith("tag_") and asm_line.strip().endswith(":")) or (
                asm_line.strip().startswith("EVM assembly:")) or (
                asm_line.strip().startswith("sub_0: assembly")) or (
                asm_line.strip().startswith("=YAGOL END FLAG=")) or ('jumpi' in asm_line) or (
                'jump' in asm_line):
            if temp_list == ['INVALID']:
                loguru.logger.warning("检测到INVALID")
                pass
            if append_flag:
                if 'jumpi' in asm_line:
                    temp_list.append('JUMPI')
                else:
                    if "jump" in asm_line:
                        temp_list.append("JUMP")
                if len(temp_list) != 0:
                    bug_blocks.append(temp_list)
                    loguru.logger.info(
                        f"ASM中{append_line_number}发现漏洞基本块,{temp_list}")
                append_flag = False
                append_line_number = ""
            if asm_line.strip().startswith("tag_") and asm_line.strip().endswith(":"):
                temp_list = ["JUMPDEST"]
            else:
                temp_list = []
        else:
            for i, bug_location in enumerate(bug_source_location):
                if str(bug_location) in asm_line:
                    append_flag = True
                    append_line_number = f"{append_line_number},{str(bug_location)}"
            asm_line = asm_line.strip().upper()
            if asm_line.startswith("/*") or asm_line.startswith("0X") or asm_line.startswith("TAG_"):
                continue
            append_line = ""
            for i, char in enumerate(asm_line):
                if char == '(' or char == '/' or char == '\t':
                    break
                else:
                    append_line += char
            temp_list.append(append_line)
    return bug_blocks


def check_cfg_with_bug_blocks(_be_check_bb, _bug_blocks, _bug_ins_set) -> bool:
    """
    递归检查基本块是否含有漏洞，逻辑如下：
    对与_be_check_bb，首先判断该块是否含有bug属性，若含有，则已经检查过了，返回bug属性的值
    若没有bug属性，说明还没检查过，开始检查
    1. 对该块的指令进行删减
    2. 递归判断指令List是否和存在漏洞的指令List相等，若相等，则bug属性为True，跳出遍历。否则为False
    3. 检查这个块的outgoing块，递归本函数，用or指令连接递归的结果，这样当递归的返回True时，说明本块也含有漏洞
    :param _bug_ins_set:
    :param _be_check_bb:
    :param _bug_blocks:
    :return:
    """
    if hasattr(_be_check_bb, "bug"):
        loguru.logger.info(f"该基本块{_be_check_bb}已经检查完毕，跳过")
        return _be_check_bb.bug
    else:
        loguru.logger.info(f"正在检查块{_be_check_bb}")
    _be_check_bb.bug = False
    _be_check_bb.original_bug = False
    buggy = False
    if _bug_ins_set is not None:
        """
        策略1,判断存在漏洞的指令的pc位置，是否在该块中间
        """
        for bug_ins in _bug_ins_set:
            if _be_check_bb.start.pc <= bug_ins <= _be_check_bb.end.pc:
                _be_check_bb.bug = True
                _be_check_bb.original_bug = True
                buggy = True
                loguru.logger.warning(f"在块{_be_check_bb}定位到bug,该块的起始是{_be_check_bb.start.pc},终点是{_be_check_bb.end.pc},漏洞指令位置是{bug_ins}")
                break
    elif _bug_blocks is not None:
        """
        策略2,判断存在漏洞的基本块的指令是否与当前块的指令相同
        """
        trim_cfg_base_block = trim_cfg_base_block_ins(_be_check_bb.instructions)
        loguru.logger.info(trim_cfg_base_block)
        for bug_block in _bug_blocks:
            if bug_block == trim_cfg_base_block:
                _be_check_bb.bug = True
                _be_check_bb.original_bug = True
                buggy = True
                loguru.logger.warning(f"在块{_be_check_bb}定位到bug,该块的指令是{trim_cfg_base_block}")
                break
    else:
        loguru.logger.error("策略1和策略2的结果均为None,出现错误，请检查，程序终止")
        sys.exit(-1)
    for next_bb in _be_check_bb.all_outgoing_basic_blocks:
        # loguru.logger.info(f"基本块跳转{_be_check_bb} -> {next_bb}")
        buggy = check_cfg_with_bug_blocks(_be_check_bb=next_bb, _bug_blocks=_bug_blocks,
                                          _bug_ins_set=_bug_ins_set) or buggy
    _be_check_bb.bug = buggy
    return buggy


def trim_cfg_base_block_ins(_cfg_base_block) -> list:
    """
    将evm-cfg-builder构建的各个基本块的指令，删减无用指令，规则如下：
    PUSH指令删除
    SHA3指令转换为KECCAK256
    :param _cfg_base_block: 需要被删减的基本块指令List
    :return:删减后的List
    """
    trim_cfg_base_block = list()
    for instruction in _cfg_base_block:
        if instruction.name.startswith("PUSH"):
            continue
        else:
            if instruction.name == "SHA3":
                trim_cfg_base_block.append("KECCAK256")
            else:
                trim_cfg_base_block.append(instruction.name)
    return trim_cfg_base_block


def set_true(bb):
    bb.bug = True
    for i in bb.all_incoming_basic_blocks:
        set_true(i)


def gen_target_output(_cfg: CFG, output_dir):
    """
    生成制导JSON信息，信息如下：
    {
        0x22:true
    }
    :param _cfg: 包含制导信息，即BasicBlock.bug=True or False
    :return:
    """
    import json
    target_dict = dict()
    loguru.logger.info("正在输出制导JSON文件")
    bb_bug_count = 0
    # for bb in _cfg.basic_blocks:
    #     if bb.start.pc == 2002:
    #         set_true(bb)
    for bb in _cfg.basic_blocks:
        if hasattr(bb, "bug"):
            target_dict[hex(bb.start.pc)] = bb.bug
            if bb.bug:
                bb_bug_count += 1
        # else:
        #     target_dict[hex(bb.start.pc)]=True
    with open(f"{output_dir}/target.json", "w") as target_json:
        target_dict['target'] = True
        json.dump(target_dict, target_json)
    loguru.logger.info(
        f"制导JSON生成完毕，包含基本块{len(target_dict)}个,其中包含漏洞块{bb_bug_count}个,占比{bb_bug_count / len(target_dict) * 100}%")
    return _cfg


def gen_stop_condition(bug_infos: Dict[str, List[BugInfo]]):
    stop_condition_dict = {
        "target": {},
        "fully": {}
    }
    for line, bugs in bug_infos.items():
        for bug in bugs:
            bug_type = bug.bug_type
            start = bug.start_pos
            length = bug.length
            key = f"{start}:{start + length}"
            if key in stop_condition_dict:
                stop_condition_dict['target'][key].append({
                    "type": bug_type,
                    "detect_time": []
                })
                stop_condition_dict['fully'][key].append({
                    "type": bug_type,
                    "detect_time": []
                })
            else:
                stop_condition_dict['target'][key] = [{
                    "type": bug_type,
                    "detect_time": []
                }]
                stop_condition_dict['fully'][key] = [{
                    "type": bug_type,
                    "detect_time": []
                }]
    with open("/root/smart_target/target_file/stop_condition.json", "w") as stop_condition_json:
        json.dump(stop_condition_dict, stop_condition_json)


class ManticoreFinding:
    def __init__(self, bug_type, bug_pc, bug_source_line, bug_source_content):
        self.bug_type = bug_type
        self.bug_pc = bug_pc
        self.bug_source_line = bug_source_line
        self.bug_source_content = bug_source_content

    def __eq__(self, other):
        if isinstance(other, ManticoreFinding):
            if self.bug_type == other.bug_type:
                if self.bug_pc == other.bug_pc:
                    if self.bug_source_line == other.bug_source_line:
                        if self.bug_source_content == other.bug_source_content:
                            return True
        return False


def get_manticore_coverage_report(_mode, _output_dir) -> float:
    """
    得到指定模式下的manticore的覆盖率，返回值为浮点型

    :param _mode: manticore的模式，[target/fully]
    :param _output_dir:
    :return:
    """
    coverage = -1
    with open(f"{_output_dir}/manticore_{_mode}_out/global.summary", "r") as global_summary_file:
        try:
            coverage = float(global_summary_file.readlines()[
                             1].split(":")[1].replace("%", "").strip())
        except IndexError as e:
            loguru.logger.error(f"获取manticore覆盖率失败，错误信息：{e}")
    return coverage


def check_findings_with_slither(_mode, _output_dir, _slither_bug_infos):
    loguru.logger.info(f"正在检查{_mode}模式和slither的漏洞检测结果差异")
    manticore_findings = handle_global_findings(_mode, _output_dir)
    not_bug_type = dict()
    not_bug_line = dict()
    for source_line, bug_infos in _slither_bug_infos.items():
        if source_line in manticore_findings.keys():
            for bug_info in bug_infos:
                is_equal = False
                for manticore_bug_info in manticore_findings[source_line]:
                    if manticore_bug_info.bug_source_line == bug_info.line_num and \
                            bug_info.bug_type.upper() in manticore_bug_info.bug_type.upper():
                        is_equal = True
                        break
                if not is_equal:
                    """
                    漏洞的行数存在，但是漏洞类型或内容不匹配
                    """
                    loguru.logger.warning(
                        f"{source_line}行的漏洞类型在manticore中没有检测到")
                    if source_line not in not_bug_type.keys():
                        not_bug_type[source_line] = [bug_info]
                    else:
                        not_bug_type[source_line].append(bug_info)
        else:
            """
            该行漏洞没有被manticore检测出来
            """
            loguru.logger.error(f"{source_line}行的漏洞信息在manticore中没有检测到")
            if source_line not in not_bug_line.keys():
                not_bug_line[source_line] = [bug_infos]
            else:
                not_bug_line[source_line].append(bug_infos)
    if not_bug_type == {} and not_bug_line == {}:
        loguru.logger.info(f"{_mode}模式和slither的漏洞检测结果没有差异")
    return not_bug_type, not_bug_line, manticore_findings


def handle_global_findings(_mode, _output_dir) -> Dict[int, List[ManticoreFinding]]:
    """
    将特定模式的manticore的global_findings文件解析为ManticoreFinding类形式

    返回值如下形式：
    行号=>[漏洞1、漏洞2]

    :param _mode:
    :param _output_dir:
    :return:
    """
    manticore_findings = append_coverage_into_manticore_findings(
        _mode, _output_dir)
    manticore_findings_to_json(
        _manticore_findings=manticore_findings, _output_dir=_output_dir, _mode=_mode)
    return manticore_findings


def append_coverage_into_manticore_findings(_mode, _output_dir):
    manticore_findings = get_manticore_findings_from_str_report(
        _mode, _output_dir)
    coverage = get_manticore_coverage_report(_mode, _output_dir)
    manticore_findings['coverage'] = coverage
    return manticore_findings


def get_manticore_findings_from_str_report(_mode, _output_dir) -> Dict:
    manticore_findings = dict()
    with open(f"{_output_dir}/manticore_{_mode}_out/global.findings", "r") as global_findings_file:
        global_findings_lines = global_findings_file.readlines()
        for index, line in enumerate(global_findings_lines):
            if line.strip().startswith("Solidity snippet:"):
                try:
                    bug_type = global_findings_lines[index -
                                                     2].replace("-", "").strip()
                    bug_pc = global_findings_lines[index -
                                                   1].split("EVM Program counter:")[1].split()
                    bug_source_line = global_findings_lines[index + 1].strip().split("  ")[
                        0]
                    bug_source_content = global_findings_lines[index + 1].strip().split("  ")[
                        1]
                    finding = ManticoreFinding(bug_type, bug_pc, int(
                        bug_source_line), bug_source_content)
                    if int(bug_source_line) not in manticore_findings.keys():
                        manticore_findings[int(bug_source_line)] = [finding]
                    else:
                        manticore_findings[int(
                            bug_source_line)].append(finding)
                except Exception as e:
                    loguru.logger.error(
                        f"检查{_mode}模式的global_findings文件的{index}行时出现错误, {e}")
    return manticore_findings


def slither_report_to_json(_slither_report, _output_dir):
    with open(f"{_output_dir}/slither_report.json", "w") as slither_report_file:
        json.dump(fp=slither_report_file, obj=_slither_report, cls=JsonEncoder)


def manticore_findings_to_json(_manticore_findings, _output_dir, _mode):
    with open(f"{_output_dir}/{_mode}_manticore_findings.json", "w") as manticore_findings_file:
        json.dump(fp=manticore_findings_file,
                  obj=_manticore_findings, cls=JsonEncoder)


class JsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, BugInfo):
            return o.__dict__
        if isinstance(o, ManticoreFinding):
            return o.__dict__


def gen_state_written_target(sl: Slither, bug_infos, contract_name):
    """
    分析原始漏洞，所在的函数在哪，这个函数读取的状态变量。
    然后遍历整个合约的函数，对于其他函数，看看他写入的状态变量是什么，然后将这行加入到bug_infos里，特殊标记是written_target
    不仅分析直接读取的状态变量，还需要分析他所引用的函数修饰器所读取的变量(启发式例子unchecked_low_level_calls/0xb620cee6b52f96f3c6b253e6eea556aa2d214a99.sol)
    :param sl:
    :param bug_infos:
    :param contract_name:
    :return:
    """
    bug_lines = list(bug_infos.keys())
    to_be_find_state_vars = set()
    to_be_find_state_vars_in_modifier = set()
    to_be_find_state_vars_in_function = set()
    state_var_mapper = {}
    mapping_type_state_var_name = set()
    internal_buggy_func_name = set()
    for contract in sl.contracts:
        if contract.name == contract_name:
            function_should_be_add = set()
            state_var_names = set([v.name for v in contract.all_state_variables_written])
            struct_var_names = set([s.name for s in contract.structures])  # 所有的结构体名称
            for state_var in contract.all_state_variables_written:  # 被修改的状态变量
                # 将被修改的状态变量添加进set里, 似乎是重复了?
                state_var_names.add(state_var.name)
                # 如果这个状态变量是mapping, 判断他的mapping第二部分是不是结构体
                if isinstance(state_var.type, MappingType):
                    if len(state_var.signature) == 3:
                        state_var_signature = state_var.signature[2]
                        for st in struct_var_names:  # 遍历结构体名字
                            if st in state_var_signature:  # 他的映射关系中含有结构体
                                # 添加到这个set里, 如果漏洞函数里这个mapping被读取了, 那么这个mapping的"读取后修改"语句是额外目标
                                mapping_type_state_var_name.add(state_var.name)
                                loguru.logger.debug("存在mapping, 且被映射对象为结构体")
            for f in contract.functions:
                deep_check = False
                # if f.function_type == FunctionType.CONSTRUCTOR:
                #     continue
                if "lines" in f.source_mapping.keys():
                    for f_line in f.source_mapping['lines']:
                        if f_line in bug_lines:  # 漏洞在这个函数里，这个函数的所有读取的状态变量，都是目标
                            if f.visibility == 'internal':  # 如果这个函数是internal函数, 那么这个函数无法被直接调用 , 最后需要去寻找调用这个函数的public函数
                                # 在这个functions小循环结束之后, 再去所有的funtions里找到调用这个internal函数的public函数
                                internal_buggy_func_name.add(f.full_name)
                                loguru.logger.debug(f"寻找到的漏洞位于internal函数里:{f.full_name}")
                            temp_set = set([v.name for v in f.state_variables_read])  # 漏洞读取的状态变量
                            for temp_set_one in temp_set:
                                # 添加进set, 当这个sl的大循环结束, 将寻找这些"被漏洞读取的状态变量" 的语句
                                to_be_find_state_vars.add(temp_set_one)
                                to_be_find_state_vars_in_function.add(temp_set_one)
                            for m in f.modifiers:  # 寻找漏洞函数的修饰器所需要被读取的状态变量, 这些被读取的状态变量同样是污点目标
                                temp_set_m_read = set([v.name for v in m.state_variables_read])
                                for temp_set_one in temp_set_m_read:
                                    to_be_find_state_vars.add(temp_set_one)
                                    to_be_find_state_vars_in_modifier.add(temp_set_one)
                                loguru.logger.debug(f"寻找到的漏洞存在modifiers, 该modifiers的名称为{m.full_name}")
                            for library_call in f.library_calls:  # 寻找漏洞函数的库函数调用, 若不把他们作为目标, 那么库函数无法执行
                                for l_c in library_call:
                                    if isinstance(l_c, FunctionContract):
                                        line_l_c_num = l_c.source_mapping['lines'][0]
                                        start_l_c_pos = l_c.source_mapping['start']
                                        length_l_c = l_c.source_mapping['length']
                                        l_c_name = l_c.canonical_name
                                        if line_l_c_num in bug_infos.keys():
                                            bug_infos[line_l_c_num].append(BugInfo(start_l_c_pos, length_l_c, l_c_name, "written_target", line_l_c_num, {}, {}))
                                        else:
                                            bug_infos[line_l_c_num] = [BugInfo(start_l_c_pos, length_l_c, l_c_name, "written_target", line_l_c_num, {}, {})]
                                        loguru.logger.debug(f"寻找到的漏洞存在库函数调用, 该库函数调用的名字为{l_c_name}")
                            bug_lines.remove(f_line)
                            deep_check = True  # 这个函数是漏洞函数, 需要进一步对内部的语句中, hash调用语句进行检测
                else:  # 这个函数没有lines?
                    loguru.logger.debug("这个函数没有lines")
                    continue
                be_check_in_right_mapping_type_var = set()
                for e in f.expressions:
                    # 确认ppt里那个例子是因为hash签名么? 我怎么感觉是因为internal问题, 需要确认, 也就是关闭这个能否检测
                    # 通过实验确认过了, 确实需要这个组件, /root/smartbugs/dataset/unchecked_low_level_calls/0x7d09edb07d23acb532a82be3da5c17d9d85806b4.sol
                    # 这里在寻找这个漏洞函数, 内部是否存在基于hash签名的调用
                    if deep_check and isinstance(e, CallExpression):
                        if len(e.arguments) == 1 and isinstance(e.arguments[0], TypeConversion) and isinstance(e.arguments[0].expression, CallExpression) and len(e.arguments[0].expression.arguments) == 1 and isinstance(e.arguments[0].expression.arguments[0], Literal) and e.arguments[0].expression.type_call == "bytes32":
                            # 这是一个单层次的bytes4(keccak256)调用, 现在需要提取他的函数名字
                            function_name_use_keccak256 = e.arguments[0].expression.arguments[0].value
                            function_should_be_add.add(function_name_use_keccak256)  # 将这个漏洞函数调用的hash签名函数添加进去, 当这个functions的小循环结束, 再次循环function寻找这个函数
                            loguru.logger.debug(
                                f"该函数是漏洞函数, 并且存在通过hash进行调用的情况, 该漏洞函数名字为{f.full_name}")
                    # 这里在为这个函数(无论是不是漏洞), 所有的赋值语句进行位置记录, 以便在sl大循环结束后, 根据漏洞函数读取的状态变量, 进行额外目标的设置
                    if isinstance(e, AssignmentOperation):
                        left = str(e.expression_left)  # 语句的左边就是被赋值对象了
                        for state_var in state_var_names:
                            if state_var in left:  # 如果左边的被赋值的对象，是状态变量的话
                                if state_var not in state_var_mapper.keys():  # 将这个语句的源代码位置，添加到待检测库
                                    state_var_mapper[state_var] = [
                                        (str(e.source_mapping['start']),
                                         str(e.source_mapping['length']),
                                         str(e.source_mapping['lines'][0]),
                                         str(e)
                                         )
                                    ]
                                else:
                                    state_var_mapper[state_var].append(
                                        (
                                            str(e.source_mapping['start']),
                                            str(e.source_mapping['length']),
                                            str(e.source_mapping['lines'][0]),
                                            str(e)
                                        )
                                    )
            # 不是所有的mapping映射结构体的状态变量,都是我们的目标, 我们只想要和漏洞相关的状态变量
            mapping_type_state_var_name = mapping_type_state_var_name & to_be_find_state_vars
            for f in contract.functions:  # 漏洞的函数都确认完毕了, 接下来需要寻找3个东西, hash签名函数, internal内部调用, 读取并调用mapping结构体的语句
                if f.full_name in function_should_be_add:  # 这些函数是被漏洞函数通过hash调用的,添加目标
                    temp_line_num = f.source_mapping['lines'][0]
                    temp_start = f.source_mapping['start']
                    temp_length = f.source_mapping['length']
                    if temp_line_num in bug_infos.keys():  #
                        bug_infos[temp_line_num].append(BugInfo(temp_start, temp_length, f.full_name, 'written_target', temp_line_num, {}, {}))
                    else:
                        bug_infos[temp_line_num] = [BugInfo(temp_start, temp_length, f.full_name, 'written_target', temp_line_num, {}, {})]
                    for m in f.modifiers:  # 寻找这个函数的修饰器所需要被读取的状态变量, 这些被读取的状态变量同样是污点目标
                        temp_set_m_read = set([v.name for v in m.state_variables_read])
                        for temp_set_one in temp_set_m_read:
                            to_be_find_state_vars.add(temp_set_one)
                            to_be_find_state_vars_in_modifier.add(temp_set_one)
                    function_should_be_add.remove(f.full_name)
                for e in f.expressions:
                    # 寻找调用internal函数的函数调用语句, 将这个语句以及函数作为目标, 否则无法触发存在漏洞的internal函数的语句
                    for internal_func in internal_buggy_func_name:
                        # 如果这个函数就是需要被调用的函数, 或者这个函数不是public可以直接调用的函数, 跳过
                        if f.full_name == internal_func or f.visibility != 'public':
                            continue
                        # 这个语句首先是调用语句, 然后调用的对象是标识符, 并且这个标识符的值是函数名称, 最后他的函数名称是我们想要的internal函数名称
                        if isinstance(e, CallExpression) and isinstance(e.called, Identifier) and isinstance(e.called.value, FunctionContract) and e.called.value.full_name == internal_func:
                            temp_line_num = f.source_mapping['lines'][0]
                            temp_start = f.source_mapping['start']
                            temp_length = f.source_mapping['length']
                            if temp_line_num in bug_infos.keys():
                                bug_infos[temp_line_num].append(BugInfo(temp_start, temp_length, f.full_name, 'written_target', temp_line_num, {}, {}))
                            else:
                                bug_infos[temp_line_num] = [BugInfo(temp_start, temp_length, f.full_name, 'written_target', temp_line_num, {}, {})]
                            temp_line_num = e.source_mapping['lines'][0]
                            temp_start = e.source_mapping['start']
                            temp_length = e.source_mapping['length']
                            if temp_line_num in bug_infos.keys():
                                bug_infos[temp_line_num].append(BugInfo(temp_start, temp_length, f.full_name, 'written_target_inner_func_call_s', temp_line_num, {}, {}))
                            else:
                                bug_infos[temp_line_num] = [BugInfo( temp_start, temp_length, f.full_name, 'written_target_inner_func_call_s', temp_line_num, {}, {})]
                    # 寻找mapping相关的语句
                    if isinstance(e, AssignmentOperation):
                        # 语句的左边是被赋值对象, 如果这个被赋值对象是基于mapping映射结构体而生成的, 那么就是我们的目标了
                        left = str(e.expression_left)
                        right_m = str(e.expression_right)
                        for state_var in mapping_type_state_var_name:
                            if state_var in right_m:
                                be_check_in_right_mapping_type_var.add(left)
                        for be_checked in be_check_in_right_mapping_type_var:
                            if be_checked in left:
                                temp_line_num = e.source_mapping['lines'][0]
                                temp_start = e.source_mapping['start']
                                temp_length = e.source_mapping['length']
                                if temp_line_num in bug_infos.keys():
                                    bug_infos[temp_line_num].append(BugInfo(temp_start, temp_length, be_checked, 'written_target_struct_write', temp_line_num, {}, {}))
                                else:
                                    bug_infos[temp_line_num] = [BugInfo(temp_start, temp_length, be_checked, 'written_target_struct_write', temp_line_num, {}, {})]
                                temp_line_num = f.source_mapping['lines'][0]
                                temp_start = f.source_mapping['start']
                                temp_length = f.source_mapping['length']
                                if temp_line_num in bug_infos.keys():  # 将这个通过mapping写入状态变量的语句, 所在的函数也作为目标, 否则光有语句, 因为cfg不全的原因, 可能无法制导过去
                                    bug_infos[temp_line_num].append(BugInfo(temp_start, temp_length, be_checked, 'written_target', temp_line_num, {}, {}))
                                else:
                                    bug_infos[temp_line_num] = [BugInfo(temp_start, temp_length, be_checked, 'written_target', temp_line_num, {}, {})]
                                loguru.logger.debug("该函数存在mapping类型的间接引用修改")
    if to_be_find_state_vars_in_function | to_be_find_state_vars_in_modifier!=to_be_find_state_vars:
        loguru.logger.error("直接修改和修饰器修改之和不等于总量之和")
    for t in to_be_find_state_vars:
        if t in state_var_mapper.keys():
            for a in state_var_mapper[t]:
                start = int(a[0])
                length = int(a[1])
                line_number = int(a[2])
                source_code_content = a[3]
                infomation="written_target"
                if t in to_be_find_state_vars_in_function and t not in to_be_find_state_vars_in_modifier:
                    infomation="written_target_function"
                if t in to_be_find_state_vars_in_modifier and t not in to_be_find_state_vars_in_function:
                    infomation="written_target_modifier"
                if t in to_be_find_state_vars_in_modifier and t in to_be_find_state_vars_in_function:
                    infomation="written_target_function_and_modifier"
                if line_number in bug_infos.keys():  # 这个line出现过，直接append
                    bug_infos[line_number].append( BugInfo(start, length, source_code_content, infomation, line_number, {}, {}))
                else:
                    bug_infos[line_number] = [BugInfo(start, length, source_code_content, infomation, line_number, {}, {})]  # 没出现过，初始化list
    # bug_infos[29]=[BugInfo(739,91,"?","?",29,{},{})]
    # bug_infos[87] = [BugInfo(1605, 19, "?", "?", 87, {}, {})]
    # bug_infos[131] = [BugInfo(2434, 30, "?", "?", 131, {}, {})]
    return bug_infos
