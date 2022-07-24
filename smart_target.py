"""
Smart-Target目标制导工具
@author: yagol
1. 全部尝试用`solc 0.4.25`版本进行编译
"""
import json
from multiprocessing import Pool
import os
import shutil
import time

import utils.slither_utils
import utils.my_utils
import utils.solc_utils
import utils.cfg_utils
import utils.mythril_utils
import utils.plot_utils
from utils.smart_bugs_info_utils import get_people_bugs_info, get_smart_bugs_info
from utils.solc_utils import compile_sol
import loguru
import smart_target_config

THIS_FILE_DIR = os.path.dirname(os.path.abspath(__file__))

FULLY_MODE = "fully"
TARGET_MODE = "target"
NONE_MODE = "none"
MODEL_SELECT = FULLY_MODE

SLITHER_SOURCE = 'slither'  # 漏洞信息由slither获得
SMART_BUGS_SOURCE = 'smart_bugs'  # 漏洞信息由smartbugs的数据集中的truth获得
PEOPLE_SOURCE = "people"  # 直接指定行数
BUG_INFO_SOURCE = SLITHER_SOURCE

BUG_INFO_MODE_EACH = "each"  # 将漏洞逐一进行实验,不支持slither配合each, 因为slither不会标记origin_bug, 因此无法each
BUG_INFO_MODE_FULL = "full"  # 全部漏洞作为一批进行实验
BUG_INFO_MODE = BUG_INFO_MODE_FULL

WRITTEN_MODE_OPEN = 'open'
WRITTEN_MODE_CLOSE = 'close'
WRITTEN_MODE = WRITTEN_MODE_OPEN

TIME_LIMIT_HALF_AN_HOUR = 60 * 30
TIME_LIMIT_8_HOURS = 60 * 60 * 8
TIME_LIMIT = TIME_LIMIT_8_HOURS

smart_bugs_dataset_dir = os.path.join(THIS_FILE_DIR, "dataset")


def init_smartbugs_datasets():
    datasets = []
    for root, dirs, files in os.walk(smart_bugs_dataset_dir):
        for file in files:
            if file.endswith(".sol"):
                path = os.path.join(root, file)
                try:
                    cy = compile_sol(path)
                    for i in cy.compilation_units[path].contracts_names:
                        datasets.append((path, i))
                except BaseException as e:
                    loguru.logger.warning(f"{path}编译错误")
    return datasets


def get_origin_bug_infos(test_sol_path):
    """
    获得漏洞信息, 包括起始位置, 长度, 内容.
    这里仅获得原始漏洞信息, 不包含额外目标
    """
    time1 = time.time()  # 静态分析开始
    if BUG_INFO_SOURCE == SLITHER_SOURCE:
        # 利用slither获得漏洞信息
        bug_infos, contract_line_map, sl = utils.slither_utils.get_slither_results(_sol_path=test_sol_path)
    elif BUG_INFO_SOURCE == SMART_BUGS_SOURCE:
        sl = utils.slither_utils.get_slither_only(_sol_path=test_sol_path)
        contract_line_map = dict()
        for contract_unit in sl.contracts:
            contract_line_map[contract_unit.name] = contract_unit.source_mapping_str
        # 将smartbugs的truth作为漏洞信息
        bug_infos = get_smart_bugs_info(_sol_path=test_sol_path, _sl=sl)
    elif BUG_INFO_SOURCE == PEOPLE_SOURCE:
        sl = utils.slither_utils.get_slither_only(_sol_path=test_sol_path)
        contract_line_map = dict()
        for contract_unit in sl.contracts:
            contract_line_map[contract_unit.name] = contract_unit.source_mapping_str
        # 人工标注漏洞位置: 75,89,111
        bug_infos = get_people_bugs_info(_sol_path=test_sol_path, _sl=sl, _bug_lines=[66, 72, 90], _category="people")
    time2 = time.time()  # 静态分析结束
    return time1, time2, bug_infos, contract_line_map, sl


def gen_target_json_by_bug_infos(bug_infos, test_sol_path, contract_line_map, sl, output_dir, contract_name, time1,
                                 time2):
    # 将bug_infos展开, 将内部的函数声明暴露在最外层 ,从而能够被src_map定位到
    unflod_bug_infos = {}
    for line_num, bug_info in bug_infos.items():
        for one_bug_info in bug_info:
            if line_num in unflod_bug_infos.keys():
                unflod_bug_infos[line_num].append(one_bug_info)
            else:
                unflod_bug_infos[line_num] = [one_bug_info]
            if one_bug_info.func_sig != "":
                func_bug_info = one_bug_info.func_sig
                func_bug_info_line_num = func_bug_info.line_num
                if func_bug_info_line_num in unflod_bug_infos.keys():
                    unflod_bug_infos[func_bug_info.line_num].append(func_bug_info)
                else:
                    unflod_bug_infos[func_bug_info.line_num] = [func_bug_info]
    bug_infos = unflod_bug_infos

    time3 = time.time()  # 制导信息生成开始
    compile_result = utils.solc_utils.compile_sol(_sol_path=test_sol_path)
    compilation_units = compile_result.compilation_units[f"{test_sol_path}"]
    bin_runtime = compilation_units.bytecodes_runtime[contract_name]
    cfg = utils.cfg_utils.create_cfg(_runtime_bytecode=bin_runtime)
    if cfg is None:
        return None, bug_infos, contract_line_map[contract_name], None, None, None
    runtime_src_map = utils.my_utils.gen_sources_map(compile_unit=compilation_units, contract_name=contract_name)
    if WRITTEN_MODE == WRITTEN_MODE_OPEN:
        bug_infos = utils.my_utils.gen_state_written_target(sl, bug_infos, contract_name)  # 分析写入变量，将其作为bug目标点去定位
    cfg_with_target, chose_method = utils.my_utils.located_base_block_from_bug_infos(_cfg=cfg, _sol_path=test_sol_path,
                                                                                     _bug_infos=bug_infos,
                                                                                     _src_map=runtime_src_map,
                                                                                     _output_dir=output_dir,
                                                                                     _contract_name=contract_name)
    time4 = time.time()  # 制导信息生成结束
    return cfg_with_target, bug_infos, contract_line_map[contract_name], chose_method, time2 - time1, time4 - time3


def gen_target_json(test_sol_path, contract_name, output_dir):
    """
    制导信息生成
    :param test_sol_path: 被测sol文件绝对地址
    :param output_dir: 输出的文件夹
    :param contract_name: 被测合约名称
    :return:
    """
    time1, time2, bug_infos, contract_line_map, sl = get_origin_bug_infos(test_sol_path)
    if bug_infos is None:
        return None, None, None, None, None, None
    for k, v in bug_infos.items():
        loguru.logger.debug(f"在{k}行发现{len(v)}个漏洞")
    if BUG_INFO_MODE == BUG_INFO_MODE_FULL:  # 将所有的BugInfo作为目标
        cfg_with_target, bug_infos, line_map, chose_method, slither_used_time, target_gen_used_time = gen_target_json_by_bug_infos(
            bug_infos, test_sol_path, contract_line_map, sl, output_dir, contract_name, time1, time2)
        return cfg_with_target, bug_infos, line_map, chose_method, slither_used_time, target_gen_used_time, output_dir
    elif BUG_INFO_MODE == BUG_INFO_MODE_EACH:  # 逐一将BugInfo作为目标, 得到的数据都是数组类型的
        cfg_with_target, returned_bug_infos, line_map, chose_method, slither_used_time, target_gen_used_time, target_info_output_dir = [], [], [], [], [], [], []
        origin_bug_index = 0
        for line_num, bug_info_list in bug_infos.items():
            for bug_info in bug_info_list:
                if bug_info.origin_bug:
                    single_bug_infos = {
                        line_num: [bug_info]
                    }
                    origin_bug_each_output_dir = os.path.join(output_dir, str(origin_bug_index))
                    os.makedirs(origin_bug_each_output_dir)
                    origin_bug_index += 1
                    res_cfg_with_target, res_bug_infos, res_line_map, res_chose_method, res_slither_used_time, res_target_gen_used_time = gen_target_json_by_bug_infos(
                        single_bug_infos, test_sol_path, contract_line_map, sl, origin_bug_each_output_dir,
                        contract_name, time1, time2)
                    cfg_with_target.append(res_cfg_with_target)
                    returned_bug_infos.append(res_bug_infos)
                    line_map.append(res_line_map)
                    chose_method.append(res_chose_method)
                    slither_used_time.append(res_slither_used_time)
                    target_gen_used_time.append(res_target_gen_used_time)
                    target_info_output_dir.append(origin_bug_each_output_dir)

        return cfg_with_target, returned_bug_infos, line_map, chose_method, slither_used_time, target_gen_used_time, target_info_output_dir


def target_one(sol_file_path, output_dir, contract_name, solc_version):
    """
    output_dir实际上是基础dir, 如果是单一目标制导, 会在output_dir的基础上继续分为/1 /2 /3 等等
    如果是全部制导, 那么会直接把结果放到output_dir里
    """
    multiprocess_task_args = []
    time1 = time.time()
    cfg_with_target, bug_infos, line_map, chose_method, slither_used_time, target_gen_used_time, target_info_output_dir = gen_target_json(
        sol_file_path, contract_name, f"{output_dir}")
    if cfg_with_target is None:
        loguru.logger.error(f"{sol_file_path},{contract_name}无法生成制导信息")
        with open(f"{output_dir}/smart_target.json", "w") as f:
            json.dump({"success": False,
                       "reason": "cfg error"}, f)
        return
    # debug使用, 注意！不能在EACH模式使用, 因为该模式cfg_with_target是list
    # utils.plot_utils.plot_cfg_with_target(cfg_with_target, contract_name)
    # utils.plot_utils.plot_cfg_without_target(cfg_with_target,contract_name)
    # utils.plot_utils.plot_cfg_use_evm_cfg_builder(cfg_with_target)
    if BUG_INFO_MODE == BUG_INFO_MODE_FULL:
        task = run_mythril(sol_file_path, output_dir, contract_name, solc_version, time1,
                           cfg_with_target, bug_infos, chose_method, slither_used_time, target_gen_used_time,
                           target_info_output_dir)
        return [task]
    elif BUG_INFO_MODE == BUG_INFO_MODE_EACH:
        assert len(cfg_with_target) == len(bug_infos)
        origin_bug_total_size = len(cfg_with_target)
        for index in range(origin_bug_total_size):
            one_cfg_with_target = cfg_with_target[index]
            one_bug_infos = bug_infos[index]
            one_chose_method = chose_method[index]
            one_slither_used_time = slither_used_time[index]
            one_target_gen_used_time = target_gen_used_time[index]
            one_target_info_output_dir = target_info_output_dir[index]
            task = run_mythril(sol_file_path, one_target_info_output_dir, contract_name, solc_version, time1,
                               one_cfg_with_target, one_bug_infos, one_chose_method, one_slither_used_time,
                               one_target_gen_used_time, one_target_info_output_dir)
            multiprocess_task_args.append(task)
        return multiprocess_task_args


def run_mythril(sol_file_path, output_dir, contract_name, solc_version, time1, cfg_with_target, bug_infos, chose_method,
                slither_used_time, target_gen_used_time, target_info_output_dir):
    time2 = time.time()
    with open(f"{target_info_output_dir}/smart_target.json", "w") as f:
        json.dump({"target_gen": time2 - time1,
                   "slither_used_time": slither_used_time,
                   "target_gen_used_time": target_gen_used_time,
                   "mythril_with_target": 0,
                   "mythril_fully": 0,
                   "chose_method": chose_method,
                   "success": True,
                   "reason": "success ok",
                   "target_time_out": True,
                   "fully_time_out": True}, f)
    with open(f"{target_info_output_dir}/slither.json", "w") as f:
        json.dump(bug_infos, f, default=lambda o: o.__dict__)
    return (3, sol_file_path, contract_name, target_info_output_dir, solc_version, TIME_LIMIT,
            f"{target_info_output_dir}/smart_target.json")


def smart_target_one(sol_file_path, contract_name, output_dir, solc_version):
    os.makedirs(output_dir)
    loguru.logger.info(f"准备执行的sol文件: {sol_file_path}_{contract_name}")
    tasks = target_one(sol_file_path, output_dir, contract_name, solc_version)
    return tasks


if __name__ == '__main__':

    base_out_put_dir = os.path.join(THIS_FILE_DIR, "result")
    unique_str = time.time()
    unique_str = str(unique_str) + f":{MODEL_SELECT}:{BUG_INFO_SOURCE}:{BUG_INFO_MODE}:{WRITTEN_MODE}:{TIME_LIMIT}"
    start_time = time.time()
    os.makedirs(os.path.join(base_out_put_dir, unique_str))
    loguru.logger.add(os.path.join(base_out_put_dir, unique_str, "log.log"))
    solc_version_str = "0.4.25"
    utils.solc_utils.change_solc_version(solc_version_str)

    skip_set = []
    tasks_process = []
    for a, b, c, d in smart_target_config.SKIP_SOL_CONTRACT_NAME_PAIR:
        if d == 'cfg error' or d == 'ASM策略' or d == "too slow":
            skip_set.append((a, b, c))
    for sol_file_path, contract_name in init_smartbugs_datasets():
        file_name = sol_file_path.split("/")[-1].split(".")[0]  # 不含'.sol'
        category = sol_file_path.split("/")[-2]
        output_dir = f"{base_out_put_dir}/{unique_str}/{category}/{file_name}:{contract_name}"
        if (category, file_name, contract_name) in skip_set:
            loguru.logger.info(f"跳过{(category, file_name, contract_name)}")
            skip_set.remove((category, file_name, contract_name))
            continue
        temp_n = len(tasks_process)
        tasks = smart_target_one(sol_file_path, contract_name, output_dir, solc_version_str)
        if tasks is None:
            loguru.logger.error("tasks为空, 跳过")
            continue
        tasks_process.extend(tasks)
        assert temp_n + len(tasks) == len(tasks_process)
    assert len(set(tasks_process)) == len(tasks_process)
    pool = Pool(processes=7)
    for t in tasks_process:
        if MODEL_SELECT == FULLY_MODE:
            pool.apply_async(utils.mythril_utils.run_mythril_without_target, args=t)
        if MODEL_SELECT == TARGET_MODE:
            pool.apply_async(utils.mythril_utils.run_mythril, args=t)
        if MODEL_SELECT == NONE_MODE:
            pass
    pool.close()
    pool.join()
    loguru.logger.info(f"所有任务执行完成,输出文件夹: {base_out_put_dir}/{unique_str}")
    loguru.logger.info(f"共耗时: {time.time() - start_time}")
    if os.path.exists(os.path.join(THIS_FILE_DIR, "nohup.out")):
        shutil.copyfile(os.path.join(THIS_FILE_DIR, "nohup.out"), f"{base_out_put_dir}/{unique_str}/nohup.out.cp.log")
